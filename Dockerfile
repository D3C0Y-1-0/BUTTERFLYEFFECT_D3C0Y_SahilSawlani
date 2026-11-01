# ATHENA on Render (or any Docker host): one container serves the API, the live stream and the built website.
FROM node:20-slim AS web
WORKDIR /w
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 OMP_NUM_THREADS=2 DECOY_DEMO=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
COPY requirements-render.txt .
RUN pip install --no-cache-dir -r requirements-render.txt
# Optional: the learned PPO responder needs PyTorch (about 200 MB). Without it ATHENA falls back to the search responder and says so.
ARG WITH_TORCH=0
RUN if [ "$WITH_TORCH" = "1" ]; then pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu; fi
COPY backend ./backend
COPY data ./data
COPY --from=web /w/dist ./frontend/dist
EXPOSE 10000
CMD ["sh", "-c", "uvicorn decoy.api:app --app-dir backend --host 0.0.0.0 --port ${PORT:-10000} --log-level warning"]
