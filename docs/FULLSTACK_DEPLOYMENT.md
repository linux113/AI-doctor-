# AI Doctor full-stack deployment

## Architecture

Browser -> AWS Amplify (Next.js) -> API Gateway -> Lambda/FastAPI

The Next.js dashboard can use either:
- `NEXT_PUBLIC_API_BASE_URL` for direct browser-to-API calls, or
- the existing same-origin Next.js proxy using `AIDOCTOR_BACKEND_ORIGIN`.

The backend supports optional DynamoDB persistence through `AIDOCTOR_DYNAMODB_TABLE`.

## Amplify

Set the application root to `frontend`.

Recommended environment variables:

```text
NEXT_PUBLIC_API_BASE_URL=https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com
AIDOCTOR_BACKEND_ORIGIN=https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com
```

Do not put `AIDOCTOR_API_TOKEN` in a `NEXT_PUBLIC_*` variable.

The repository contains `amplify.yml` with the monorepo build configuration.

## Lambda

The handler is:

```text
backend.lambda_handler.handler
```

Build dependencies with:

```powershell
pip install -r requirements-lambda.txt -t lambda_build
```

Copy the repository Python packages required by the handler into the same deployment directory, then create the Lambda zip. Configure API Gateway to use the Lambda integration.

## DynamoDB

For persistent incident history, create a DynamoDB table with:

- Table name: your chosen value
- Partition key: `incident_id` (String)

Then set:

```text
AIDOCTOR_DYNAMODB_TABLE=your-table-name
```

The backend status endpoint reports whether persistence is active.

## Important Ollama boundary

The recovery runner controls a real local Ollama process on the machine where the runner executes. A Lambda function is not that machine. Lambda execution environments are ephemeral and should not be treated as long-lived hosts for local services.

Therefore, a public Lambda deployment can report `OLLAMA_NOT_INSTALLED` unless Ollama is provided by a separate persistent runner host. For the full `DETECT -> DIAGNOSE -> FIX -> VERIFY -> RETRY` Ollama demo, run the Doctor Runner on a persistent host with Ollama installed and connect the control plane to that runner.

Do not change `OLLAMA_NOT_INSTALLED` to `healthy` without a real Ollama runtime.

## Local development

From the repository root:

```powershell
pip install -r requirements-core.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Then:

```powershell
cd frontend
npm ci
npm run dev
```

Leave `NEXT_PUBLIC_API_BASE_URL` empty locally if you want the Next.js proxy to call `127.0.0.1:8000`.
