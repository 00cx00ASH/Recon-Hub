// Command reconhub-cli is a thin terminal client for a running recon-hub —
// for driving the hub from a shell instead of the dashboard or curl.
//
// Config (env): RECONHUB_URL (default http://127.0.0.1:7878), RECONHUB_TOKEN
// (else it reads ./data/token relative to the working dir, same convention
// as cmd/reconhub-mcp).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	h := newHubClient()
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "tools":
		err = cmdTools(h, args)
	case "tool":
		err = cmdTool(h, args)
	case "programs":
		err = cmdPrograms(h, args)
	case "run":
		err = cmdRun(h, args)
	case "jobs":
		err = cmdJobs(h, args)
	case "job":
		err = cmdJob(h, args)
	case "pipelines":
		err = cmdPipelines(h, args)
	case "pipeline":
		err = cmdPipeline(h, args)
	case "findings":
		err = cmdFindings(h, args)
	case "triage":
		err = cmdTriage(h, args)
	case "coverage":
		err = cmdCoverage(h, args)
	case "watches":
		err = cmdWatches(h, args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `reconhub-cli — cliente de terminal pro recon-hub

uso: reconhub-cli <comando> [args]

  tools                                    lista as ferramentas registradas
  tool <nome>                              detalhe de 1 ferramenta: resumo, guia, critério de finding válido
  programs                                 lista os programas/projetos
  run <ferramenta> <alvo> [flags]          dispara 1 ferramenta e acompanha até terminar
  jobs [flags]                             lista jobs
  job <id>                                 detalhe + eventos de 1 job
  pipelines                                lista as pipelines disponíveis
  pipeline <nome> <alvo> [flags]           roda 1 pipeline e acompanha até terminar
  findings [flags]                         lista findings com prioridade (score/ação)
  triage <finding-id> <veredito>           confirmed | false_positive | ignored
  coverage <programa>                      sugestões de próximo passo pro programa
  watches                                  lista os watches configurados

flags comuns: -program X  -severity X  -limit N  -param chave=valor (repetível)

env: RECONHUB_URL (default http://127.0.0.1:7878), RECONHUB_TOKEN
`)
}
