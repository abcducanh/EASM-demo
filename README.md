# EASM Python Demo



## Tính năng chính
- Quản lý assets domain/ip
- Scan jobs: dns, whois, subdomain, cert_trans, asn, ip, port, ssl, tech, all
- Dashboard thống kê
- Alerts khi scan lỗi/partial, có open ports, SSL sắp hết hạn
- Asset groups / tags
- Scheduled scans theo chu kỳ phút
- Scan comparison giữa 2 lần scan gần nhất
- Export asset results ra CSV / PDF

## Chạy local
```powershell
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe run.py
```

Mở: http://localhost:8080

## Tests
```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing
.venv\Scripts\python.exe -m pytest --cov=app --cov-report=html
```

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
