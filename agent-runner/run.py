#!/usr/bin/env python3
"""Runner autônomo do agent bugbounty via Claude Agent SDK (Python).

Diferente de `@bugbounty`/`claude --agent bugbounty` (que rodam DENTRO de uma
sessão interativa do Claude Code), este script é um processo standalone —
pensado pra rodar sozinho via cron/systemd/docker, sem sessão de terminal
aberta, encadeando rodadas do "Modo exploração autônoma" descrito em
`.claude/agents/bugbounty.md` até bater um dos limites (rodadas, tempo,
custo em USD) que VOCÊ define abaixo — o script é quem faz o enforcement
duro desses limites; o que o próprio agente promete no system prompt é
defesa em profundidade, não a única barreira.

Diferenças deliberadas em relação à persona interativa:
- SEM Bash, Write, Edit, Read, Grep, Glob, WebFetch, WebSearch — só as
  tools `mcp__reconhub__hub_*` (a mesma lista do frontmatter de
  bugbounty.md, lida dinamicamente daquele arquivo). Isso é MAIS restrito
  que a persona interativa: sem sessão humana olhando por cima do ombro,
  não faz sentido dar acesso a arquivo/shell nenhum.
- Como consequência, o passo "leia data/projects/<nome>/notes.md" do
  system prompt não se aplica aqui (sem Read) — a fonte de verdade vira
  só hub_list_jobs/hub_list_findings (que, como o próprio bugbounty.md já
  diz, "nunca mentem"), e conhecimento reaproveitável usa hub_add_lesson
  em vez de arquivo solto.
- Orçamento é checado em dois níveis: por rodada (`max_turns`/
  `max_budget_usd` do SDK, contendo UMA rodada individual que fugir do
  controle) e cumulativo no processo Python (rodadas/tempo/custo total),
  que é quem decide se há uma PRÓXIMA rodada.

Config via variáveis de ambiente (veja .env.example) — carrega um `.env`
ao lado deste arquivo se existir, sem exigir dependência extra.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKError,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    query,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_MD = REPO_ROOT / ".claude" / "agents" / "bugbounty.md"

# Linha que o addendum do system prompt instrui o modelo a emitir sozinho,
# no final da resposta, quando ele mesmo decidir "parar de vez" (seção
# correspondente em bugbounty.md). É o sinal que fecha o loop mais cedo do
# que os limites de rodada/tempo/custo, sem depender de adivinhar um
# subtype de mensagem do SDK que não existe (`ResultMessage.subtype` real é
# coisas como "success"/"error_during_execution" — não um sinalizador de
# "quero continuar").
STOP_MARKER = "RECONHUB_RUNNER_STOP"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


_load_dotenv(Path(__file__).resolve().parent / ".env")


@dataclass
class Config:
    program: str
    goal: str
    model: str
    fallback_model: str | None
    max_rounds: int
    max_runtime_min: float
    max_cost_usd: float
    max_turns_per_round: int
    reconhub_url: str
    reconhub_token: str | None
    log_dir: Path


def env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def load_config() -> Config:
    program = env("AGENT_PROGRAM")
    if not program:
        sys.exit(
            "AGENT_PROGRAM não definido — qual programa (já cadastrado em "
            "./programs/<nome>.json) o runner deve explorar? "
            "Veja agent-runner/.env.example."
        )
    token = env("RECONHUB_TOKEN")
    if not token:
        token_file = env("RECONHUB_TOKEN_FILE", str(REPO_ROOT / "data" / "token"))
        try:
            token = Path(token_file).read_text().strip()
        except OSError:
            token = None
    return Config(
        program=program,
        goal=env(
            "AGENT_GOAL",
            "explore o programa de forma autônoma seguindo a metodologia "
            "da esteira (seção 'A esteira' do seu system prompt)",
        ),
        model=env("AGENT_MODEL", "claude-sonnet-5"),
        fallback_model=env("AGENT_FALLBACK_MODEL"),
        max_rounds=int(env("AGENT_MAX_ROUNDS", "20")),
        max_runtime_min=float(env("AGENT_MAX_RUNTIME_MIN", "180")),
        max_cost_usd=float(env("AGENT_MAX_COST_USD", "5.0")),
        max_turns_per_round=int(env("AGENT_MAX_TURNS_PER_ROUND", "40")),
        reconhub_url=env("RECONHUB_URL", "http://127.0.0.1:7878"),
        reconhub_token=token,
        log_dir=Path(env("AGENT_LOG_DIR", str(Path(__file__).resolve().parent / "logs"))),
    )


def discover_allowed_tools() -> list[str]:
    """Lê o frontmatter de bugbounty.md e devolve só as tools mcp__reconhub__*
    — única fonte de verdade pra essa lista, em vez de duplicá-la aqui à
    mão (se o hub ganhar uma MCP tool nova e bugbounty.md for atualizado,
    o runner acompanha sozinho sem precisar de outro commit)."""
    if not AGENT_MD.exists():
        sys.exit(f"não achei {AGENT_MD} — rode este script a partir do checkout do recon-hub")
    text = AGENT_MD.read_text()
    m = re.search(r"^tools:\s*(.+)$", text, re.MULTILINE)
    if not m:
        sys.exit(f"não achei a linha 'tools:' no frontmatter de {AGENT_MD}")
    names = [t.strip() for t in m.group(1).split(",")]
    mcp_tools = [t for t in names if t.startswith("mcp__reconhub__")]
    if not mcp_tools:
        sys.exit("frontmatter de bugbounty.md não tem nenhuma tool mcp__reconhub__ — algo mudou lá, confira à mão")
    return mcp_tools


def build_system_prompt() -> str:
    text = AGENT_MD.read_text()
    # remove o frontmatter YAML (entre as duas primeiras linhas "---") —
    # só o corpo (as regras/metodologia) vira system prompt; name/description/
    # tools do frontmatter são mecanismo de subagente do Claude Code, não
    # fazem sentido fora dele.
    parts = text.split("---", 2)
    body = parts[2] if len(parts) >= 3 else text

    addendum = f"""

## Addendum — você está rodando como processo autônomo standalone (agent-runner)

Isto NÃO é uma sessão interativa do Claude Code. Não existe humano lendo
sua resposta em tempo real nem aprovando tool call nenhuma — só as tools
`mcp__reconhub__hub_*` existem aqui (sem Bash/Read/Write/Edit/WebFetch), e
o processo Python que te invoca decide sozinho se roda mais uma rodada.
Por causa disso:

- Ignore qualquer instrução acima que mencione ler ou escrever arquivo
  (`data/projects/<nome>/notes.md` incluso) — essa ferramenta não existe
  aqui. Use `hub_list_jobs`/`hub_list_findings`/`hub_list_assets` como
  única fonte de estado, e `hub_add_lesson` pra qualquer conhecimento que
  valha a pena preservar entre rodadas/programas.
- Se bater uma pergunta que só o operador poderia responder (escopo
  ambíguo, decisão sobre um achado crítico, etc.) — pare, explique
  exatamente o que está faltando, e encerre a resposta desta rodada. Não
  invente uma resposta pra continuar sozinho.
- Programa desta execução: `{{PROGRAM}}`. Objetivo desta execução:
  {{GOAL}}. O budget de jobs/tempo é controlado pelo processo Python (não
  por você) — não pergunte por um número, ele já está sendo aplicado por
  fora.
- **Achou um finding REPORTÁVEL (score/severidade alta + `meta.confirmed`
  real, ou uma cadeia de `hub_list_chain_candidates`) → pare aqui.** Sem
  operador lendo em tempo real, seguir gerando tráfego por cima de algo
  que já merece revisão humana é o oposto do que se quer. Antes de parar,
  MONTE A PROVA: `hub_draft_finding` pra gerar o PoC/relatório a partir da
  evidência real (nunca inventada) e `hub_triage_finding` `confirmed`.
  Depois feche a resposta com o resumo + o PoC e, sozinha na última linha,
  escreva exatamente:
  {STOP_MARKER}
  Assim o operador encontra o achado já com a prova montada, não uma
  menção perdida no meio do log.
- Outras condições de "Parar de vez" (seção correspondente acima) —
  budget não é mais seu de decidir quando parar, mas findings esgotados /
  nada novo por 2-3 rodadas / pergunta que só o operador responde ainda
  valem — mesmo procedimento: feche com o resumo de praxe e, sozinha na
  última linha, escreva exatamente:
  {STOP_MARKER}
  Isso é o sinal que o processo Python usa pra não te chamar de novo.
"""
    return body + addendum


def log(fh, msg: str) -> None:
    line = f"[{datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()


def print_message(fh, msg) -> None:
    if isinstance(msg, AssistantMessage):
        if msg.error:
            log(fh, f"  ⚠ erro do modelo ({msg.model}): {msg.error}")
        for block in msg.content:
            if isinstance(block, TextBlock) and block.text.strip():
                log(fh, f"  · {block.text.strip()[:2000]}")
            elif isinstance(block, ToolUseBlock):
                log(fh, f"  → {block.name}({_short(block.input)})")
            elif isinstance(block, ToolResultBlock) and block.is_error:
                log(fh, f"  ⚠ falha em tool_use {block.tool_use_id}: {_short(block.content)}")
    elif isinstance(msg, SystemMessage) and msg.subtype == "init":
        log(fh, "  sessão inicializada (MCP conectado)")


def _short(v, limit: int = 200) -> str:
    s = str(v)
    return s if len(s) <= limit else s[:limit] + "…"


async def run_round(cfg: Config, prompt: str, session_id: str | None, budget_left_usd: float) -> ResultMessage | None:
    options = ClaudeAgentOptions(
        model=cfg.model,
        fallback_model=cfg.fallback_model,
        system_prompt=build_system_prompt()
        .replace("{PROGRAM}", cfg.program)
        .replace("{GOAL}", cfg.goal),
        mcp_servers={
            "reconhub": {
                "command": "go",
                "args": ["run", "./cmd/reconhub-mcp"],
                "env": {
                    "RECONHUB_URL": cfg.reconhub_url,
                    **({"RECONHUB_TOKEN": cfg.reconhub_token} if cfg.reconhub_token else {}),
                },
            }
        },
        tools=[],  # desliga TODAS as tools embutidas (Bash/Read/Write/Edit/...)
        allowed_tools=discover_allowed_tools(),
        disallowed_tools=["Bash", "Write", "Edit", "Read", "Grep", "Glob", "WebFetch", "WebSearch"],
        permission_mode="dontAsk",  # nunca pergunta; nega o que não está pré-aprovado
        max_turns=cfg.max_turns_per_round,
        max_budget_usd=max(0.01, budget_left_usd),
        cwd=str(REPO_ROOT),
        resume=session_id,
    )
    result: ResultMessage | None = None
    fh = getattr(run_round, "_fh", None)
    async for message in query(prompt=prompt, options=options):
        print_message(fh, message)
        if isinstance(message, ResultMessage):
            result = message
    return result


async def main() -> None:
    cfg = load_config()
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    log_path = cfg.log_dir / f"{cfg.program}-{datetime.datetime.now(datetime.UTC):%Y%m%dT%H%M%SZ}.log"
    fh = open(log_path, "a")
    run_round._fh = fh  # type: ignore[attr-defined]

    auth_mode = "API paga (ANTHROPIC_API_KEY)" if os.environ.get("ANTHROPIC_API_KEY") else "assinatura/login já configurado (claude login)"
    log(fh, f"iniciando runner autônomo — programa={cfg.program} modelo={cfg.model} auth={auth_mode}")
    log(fh, f"limites: max_rounds={cfg.max_rounds} max_runtime_min={cfg.max_runtime_min} max_cost_usd={cfg.max_cost_usd}")

    deadline = time.monotonic() + cfg.max_runtime_min * 60
    total_cost = 0.0
    session_id: str | None = None
    consecutive_errors = 0
    prompt = (
        f"Ative o 'Modo exploração autônoma'. Programa: {cfg.program}. "
        f"Objetivo: {cfg.goal}. Comece pelo passo 1 do loop (estado atual)."
    )

    for round_no in range(1, cfg.max_rounds + 1):
        if time.monotonic() >= deadline:
            log(fh, f"tempo máximo ({cfg.max_runtime_min} min) esgotado — parando antes da rodada {round_no}")
            break
        budget_left = cfg.max_cost_usd - total_cost
        if budget_left <= 0:
            log(fh, f"orçamento (${cfg.max_cost_usd} USD) esgotado — parando antes da rodada {round_no}")
            break

        log(fh, f"── rodada {round_no}/{cfg.max_rounds} (custo acumulado ${total_cost:.4f}) ──")
        try:
            result = await run_round(cfg, prompt, session_id, budget_left)
        except ClaudeSDKError as e:
            if "maximum number of turns" in str(e).lower():
                # A rodada bateu o teto de max_turns_per_round no meio da
                # narrativa (comum quando ela dispara muitos jobs/consultas
                # de status) — é só o orçamento de turns por rodada que
                # esgotou, não o modelo travado. Continuar pra próxima
                # rodada (sem resume= — a sessão morreu sem terminar limpo)
                # é seguro porque o estado real (jobs/findings já
                # disparados) já está salvo no hub; a próxima rodada relê
                # isso via hub_list_jobs/hub_list_findings, do mesmo jeito
                # que faria sem Read algum. Tratar isso como fatal jogava
                # fora até 19 rodadas ainda disponíveis por um teto
                # por-rodada baixo demais, não por falta de trabalho útil
                # a fazer.
                log(fh, f"  ⚠ rodada {round_no} bateu o teto de turns por rodada "
                        f"(max_turns_per_round={cfg.max_turns_per_round}) — "
                        f"seguindo pra próxima rodada (relendo estado do hub do zero)")
                session_id = None
                prompt = "continue"
                continue
            log(fh, f"erro de SDK/CLI: {e} — parando")
            break

        if result is None:
            log(fh, "rodada terminou sem ResultMessage (transporte encerrou cedo) — parando")
            break

        session_id = result.session_id
        total_cost += result.total_cost_usd or 0.0
        log(
            fh,
            f"rodada {round_no} concluída: subtype={result.subtype} "
            f"terminal_reason={result.terminal_reason} is_error={result.is_error} "
            f"custo_rodada=${(result.total_cost_usd or 0):.4f} custo_acumulado=${total_cost:.4f}",
        )

        if result.is_error:
            consecutive_errors += 1
            log(fh, f"  ⚠ rodada terminou em erro ({consecutive_errors} seguida(s))")
            if consecutive_errors >= 2:
                log(fh, "2 erros seguidos — parando pra não insistir num modo de falha")
                break
        else:
            consecutive_errors = 0

        if result.result and STOP_MARKER in result.result:
            log(fh, "agente sinalizou fim da exploração (marcador de parada) — encerrando")
            break

        prompt = "continue"  # o histórico já está preservado via resume=session_id

    log(fh, f"runner encerrado — custo total estimado ${total_cost:.4f}")
    fh.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\ninterrompido pelo operador (Ctrl+C)", file=sys.stderr)
