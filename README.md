# EASM Python Demo

<<<<<<< HEAD
Demo EASM backend + frontend theo flow bài tập, viết bằng Python/FastAPI.

## Checklist hoàn thiện
- Code chạy được, có health check `GET /health`
- Kiến trúc tách lớp rõ ràng theo hướng Clean Architecture đơn giản:
  - `app/api`: delivery layer / HTTP routes
  - `app/services`: business logic / use cases
  - `app/scanners`: infrastructure integrations
  - `app/models`: domain + request/response models
  - `app/storage`: persistence in-memory cho demo
- Error handling đầy đủ với `HTTPException`, validate input bằng Pydantic, timeout/fallback trong scanners
- Test được bằng curl/Postman và có test tự động bằng `pytest`
- Có comments giải thích các đoạn logic phức tạp như scan nền, discovery, schedule worker
- Có `README.md` hướng dẫn cài đặt/chạy/test/deploy
- Có `api.yml` mô tả các endpoint đã mở rộng
=======

>>>>>>> bacf5d84e542b53d689955c29b196e5ad24a5988

## Tính năng chính
- Quản lý assets domain/ip
- Scan jobs: dns, whois, subdomain, cert_trans, asn, ip, port, ssl, tech, all
- Dashboard thống kê
- Alerts khi scan lỗi/partial, có open ports, SSL sắp hết hạn
- Asset groups / tags
- Scheduled scans theo chu kỳ phút
- Scan comparison giữa 2 lần scan gần nhất
- Export asset results ra CSV / PDF
<<<<<<< HEAD
- Docker Compose cho full stack
- GitHub Actions CI/CD + security scans

## Cấu trúc dự án
```text
backend/app/
  api/        # HTTP routes / controllers
  models/     # Domain models + request schemas
  services/   # Use cases / business rules
  scanners/   # DNS/WHOIS/SSL/Port/... integrations
  storage/    # In-memory storage cho demo
frontend/     # Static HTML/CSS/JS UI
.github/      # GitHub Actions workflow
```
=======
>>>>>>> bacf5d84e542b53d689955c29b196e5ad24a5988

## Chạy local
```powershell
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe run.py
```

Mở: http://localhost:8080

<<<<<<< HEAD
## Test bằng curl
```bash
# Create assets
DOMAIN_ASSET=$(curl -s -X POST http://localhost:8080/assets   -H "Content-Type: application/json"   -d '{"name":"google.com","type":"domain"}' | jq -r '.id')

IP_ASSET=$(curl -s -X POST http://localhost:8080/assets   -H "Content-Type: application/json"   -d '{"name":"127.0.0.1","type":"ip"}' | jq -r '.id')

# Start scans
DNS_JOB=$(curl -s -X POST "http://localhost:8080/assets/$DOMAIN_ASSET/scan"   -H "Content-Type: application/json"   -d '{"scan_type":"dns"}' | jq -r '.id')

PORT_JOB=$(curl -s -X POST "http://localhost:8080/assets/$IP_ASSET/scan"   -H "Content-Type: application/json"   -d '{"scan_type":"port"}' | jq -r '.id')

# Poll status
curl -s "http://localhost:8080/scan-jobs/$DNS_JOB" | jq

# Read results
curl -s "http://localhost:8080/scan-jobs/$DNS_JOB/results" | jq
```

=======
>>>>>>> bacf5d84e542b53d689955c29b196e5ad24a5988
## Tests
```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing
.venv\Scripts\python.exe -m pytest --cov=app --cov-report=html
```

<<<<<<< HEAD
## API documentation
- `api.yml`: OpenAPI YAML snapshot cho toàn bộ endpoint hiện tại
- Ngoài ra khi chạy app, FastAPI còn có:
  - Swagger UI: `http://localhost:8080/docs`
  - ReDoc: `http://localhost:8080/redoc`

## Bài 5 - Deploy với Docker Compose
```bash
docker compose up --build -d
docker compose ps
curl http://localhost:8080/health
docker compose down
```

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8080`

## Bài 6 - Bonus features
- **Scheduled Scans**: `POST /assets/{id}/schedules`, `GET /assets/{id}/schedules`
- **Asset Groups/Tags**: tạo asset với `tags`, `PATCH /assets/{id}/tags`, `GET /asset-groups`
- **Alerts/Notifications**: `GET /alerts`
- **Scan Comparison**: `GET /assets/{id}/compare?scan_type=dns`
- **Export Reports**: `GET /assets/{id}/export.csv`, `GET /assets/{id}/export.pdf`
=======
## Bonus features (Bài 6)
- **6.1 Scheduled Scans**: `POST /assets/{id}/schedules`, `GET /assets/{id}/schedules`
- **6.2 Asset Groups/Tags**: tạo asset với `tags`, `PATCH /assets/{id}/tags`, `GET /asset-groups`
- **6.3 Alerts/Notifications**: `GET /alerts`
- **6.4 Scan Comparison**: `GET /assets/{id}/compare?scan_type=dns`
- **6.5 Export Reports**: `GET /assets/{id}/export.csv`, `GET /assets/{id}/export.pdf`


## Bài 5 - Deploy với Docker Compose

### File đã thêm
- `docker-compose.yml`
- `backend/Dockerfile`
- `frontend/Dockerfile`
- `frontend/nginx.conf`
- `.dockerignore`

### Chạy bằng Docker Compose
```bash
docker compose up --build -d
```

### Kiểm tra services
```bash
docker compose ps
```

### Kiểm tra backend health
```bash
curl http://localhost:8080/health
```

### Truy cập ứng dụng
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8080`

### Dừng stack
```bash
docker compose down
```

### Screenshot cần chụp
- `docker compose ps` hiển thị cả `easm-frontend` và `easm-backend` đang chạy
- Frontend mở được tại `http://localhost:3000`
- Backend health check trả về `{"status":"ok"}` tại `http://localhost:8080/health`
>>>>>>> bacf5d84e542b53d689955c29b196e5ad24a5988
