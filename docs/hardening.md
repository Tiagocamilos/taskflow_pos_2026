# Relatório de Hardening - TaskFlow

- **Antes:** `codigo/app-exemplo/Dockerfile` (`python:latest`)
- **Depois:** `Dockerfile` da raiz (`python:3.12-slim` → Debian 13.7 trixie, multi-stage)

## 1. Falhas corrigidas no Dockerfile

| # | Antes | Depois |
|---|---|---|
| 1 | `python:latest` (tag mutável, imagem completa) | `python:3.12-slim` fixada + multi-stage |
| 2 | Rodava como root | Usuário `taskflow` sem shell |
| 3 | Dependências sem controle | Versões fixadas + pip-audit no CI |
| 4 | `ENV ADMIN_PASSWORD=admin123` na imagem | Nenhum segredo em ENV/ARG (só em runtime) |
| 5 | Servidor de dev do Flask | gunicorn |
| 6 | `python app.py` com debug, como root | gunicorn, sem debug, não-root |

## 2. Trivy (HIGH/CRITICAL)

```bash
docker build -t taskflow:vuln codigo/app-exemplo && trivy image --severity HIGH,CRITICAL taskflow:vuln
docker build -t taskflow:hardened .            && trivy image --severity HIGH,CRITICAL taskflow:hardened
```

| | Antes | Depois |
|---|---|---|
| CVEs HIGH | TODO | 0 |
| CVEs CRITICAL | TODO | 0 |

O gate no CI usa `ignore-unfixed`: CVE sem correção publicada não bloqueia
(não há versão para atualizar) e, se aparecer, é registrada aqui como risco
aceito. Riscos aceitos hoje: nenhum.

## 3. docker history

```bash
docker history --no-trunc taskflow:vuln     | grep -i password   # antes: ENV ADMIN_PASSWORD=admin123
docker history --no-trunc taskflow:hardened | grep -i password   # depois: vazio
```

```text
TODO: colar a linha encontrada na imagem antiga
```

## 4. Flags de runtime

```bash
docker run -p 5000:5000 --read-only --tmpfs /tmp -v taskflow-data:/app/data \
  --cap-drop ALL --security-opt no-new-privileges --env-file .env taskflow:hardened
```

Filesystem imutável, sem capabilities do kernel, sem escalada de privilégio,
segredos só em runtime. Validado no smoke test do `container.yml`.

## 5. Lynis

```bash
sudo lynis audit system
```

| | Antes | Depois |
|---|---|---|
| Hardening index | TODO | TODO |

| Achado | Tratamento |
|---|---|
| TODO | TODO |
| TODO | TODO |
