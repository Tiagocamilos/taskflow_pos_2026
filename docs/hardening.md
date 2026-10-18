# Relatório de Hardening - TaskFlow

Este documento comprova a redução da superfície de ataque da imagem Docker após a aplicação das correções no `Dockerfile`.

## 1. Análise de Vulnerabilidades com Trivy

### Antes (Dockerfile Original)
*   **Imagem Base:** `python:latest` (sem tag fixa, muitos pacotes, muitas CVEs).
*   **Achados HIGH/CRITICAL:** [Insira aqui o número de vulnerabilidades que o Trivy apontou na imagem original. Ex: 150].
*   **Problemas principais:** Sistema operacional completo, bibliotecas desatualizadas, rodando como root.

### Depois (Dockerfile Hardened)
*   **Imagem Base:** `python:3.12-slim` (multi-stage, menos pacotes).
*   **Achados HIGH/CRITICAL:** [Insira aqui o número de vulnerabilidades que o Trivy aponta na imagem nova. Ex: 0 ou 2].
*   **Melhorias:** Uso de multi-stage build, remoção de ferramentas de compilação, usuário não-root.

**Comando utilizado para o scan:**
```bash
trivy image --severity HIGH,CRITICAL <nome-da-imagem>
