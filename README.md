# ⚠️ Vulnerable Lab API — Aikido DAST target

**Solo para laboratorio.** Esta API contiene vulnerabilidades **a propósito** para
que el escáner **DAST de API REST de Aikido** las detecte. No la despliegues en un
proyecto Supabase con datos reales, no la dejes expuesta más tiempo del necesario,
y **borra el proyecto Supabase al terminar**.

## Qué incluye

- `supabase/functions/api/index.ts` — Edge Function (Deno) con todas las rutas.
- `supabase/migrations/0001_init.sql` — tablas `users` y `products` con datos semilla.
- `supabase/config.toml` — `verify_jwt = false` para que el DAST alcance las rutas.
- `openapi/openapi.yaml` — spec para importar en Aikido.

## Vulnerabilidades intencionales

| Ruta | Problema (OWASP API Top 10) |
|------|------------------------------|
| `POST /login` | SQL injection + auth débil |
| `GET /users` | Sin auth, expone hashes/api_keys |
| `GET /users/{id}` | BOLA/IDOR + SQLi |
| `PUT /users/{id}` | Mass assignment (puedes ponerte `role=admin`) |
| `GET /admin/config` | Auth por token no verificado, fuga de secretos |
| `GET /fetch?url=` | SSRF |
| `GET /search?q=` | XSS reflejado |
| `POST /products` | Sin auth + SQLi |
| (todas) | CORS abierto, sin rate limiting, errores verbosos |

## Despliegue en Supabase

Requisitos: [Supabase CLI](https://supabase.com/docs/guides/cli) y una cuenta.

```bash
# 1. Login e inicializa el link con tu proyecto (crea uno NUEVO y desechable)
supabase login
supabase link --project-ref <TU_PROJECT_REF>

# 2. Aplica la migración (crea tablas + datos)
supabase db push

# 3. La función lee la conexión desde SUPABASE_DB_URL. Configúralo como secret:
#    (usa la connection string de: Project Settings > Database > Connection string)
supabase secrets set SUPABASE_DB_URL="postgresql://postgres:<PASS>@db.<REF>.supabase.co:5432/postgres"

# 4. Despliega la función
supabase functions deploy api --no-verify-jwt
```

La URL pública queda en:

```
https://<TU_PROJECT_REF>.supabase.co/functions/v1/api
```

Prueba rápida:

```bash
curl https://<TU_PROJECT_REF>.supabase.co/functions/v1/api/health
curl "https://<TU_PROJECT_REF>.supabase.co/functions/v1/api/users"
```

## Configurar el escaneo en Aikido

1. En `openapi/openapi.yaml`, sustituye `your-project-ref` por tu `PROJECT_REF`.
2. En Aikido: **DAST / API scanning** → añade la API → importa el OpenAPI.
3. Base URL: `https://<TU_PROJECT_REF>.supabase.co/functions/v1/api`.
4. Lanza el escaneo. Deberías ver hallazgos de SQLi, XSS, SSRF, BOLA, etc.

## Al terminar

Borra el proyecto Supabase (**Project Settings → General → Delete project**) para
no dejar una API vulnerable accesible.
