from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from app.models.asset import AssetUpdateTags, ScheduledScanCreate, ScanRequest, ScanType
from app.services.asset_service import AssetService
from app.services.scan_service import ScanService
from app.services.schedule_service import ScheduleService

router = APIRouter()
asset_service = AssetService()
scan_service = ScanService()
schedule_service = ScheduleService(scan_service)


@router.get('/health')
def health():
    return {'status': 'ok'}


from app.models.asset import AssetCreate

@router.post('/assets', status_code=201)
def create_asset(payload: AssetCreate):
    return asset_service.create(payload)


@router.get('/assets')
def list_assets(tag: str | None = None):
    assets = asset_service.list()
    if tag:
        assets = [asset for asset in assets if tag.lower() in asset.tags]
    return assets


@router.patch('/assets/{asset_id}/tags')
def update_asset_tags(asset_id: str, payload: AssetUpdateTags):
    try:
        return asset_service.update_tags(asset_id, payload.tags)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete('/assets/{asset_id}')
def delete_asset(asset_id: str):
    asset_service.delete(asset_id)
    return JSONResponse({'deleted': True})


@router.delete('/assets')
def delete_all_assets():
    asset_service.delete_all()
    return JSONResponse({'deleted': True})


# Start scan as an asynchronous job. The API immediately returns a pending job
# so clients can poll /scan-jobs/{id} until the worker thread finishes.
@router.post('/assets/{asset_id}/scan', status_code=202)
def start_scan(asset_id: str, payload: ScanRequest):
    try:
        asset = asset_service.get(asset_id)
        return scan_service.start_scan(asset, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/scan-jobs/{job_id}')
def get_job(job_id: str):
    try:
        return scan_service.get_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/scan-jobs/{job_id}/results')
def get_results(job_id: str):
    try:
        return scan_service.get_results(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/assets/{asset_id}/scans')
def list_scans(asset_id: str):
    return scan_service.list_scans_for_asset(asset_id)


@router.get('/assets/{asset_id}/results')
def asset_results(asset_id: str):
    return scan_service.get_all_results_for_asset(asset_id)


@router.get('/assets/{asset_id}/dns')
def asset_dns(asset_id: str):
    return scan_service.get_latest_results_by_type(asset_id, ScanType.DNS)


@router.get('/assets/{asset_id}/whois')
def asset_whois(asset_id: str):
    return scan_service.get_latest_results_by_type(asset_id, ScanType.WHOIS)


@router.get('/assets/{asset_id}/subdomains')
def asset_subdomains(asset_id: str):
    return scan_service.get_latest_results_by_type(asset_id, ScanType.SUBDOMAIN)


@router.post('/assets/{asset_id}/schedules', status_code=201)
def create_schedule(asset_id: str, payload: ScheduledScanCreate):
    try:
        asset = asset_service.get(asset_id)
        return schedule_service.create(asset, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/assets/{asset_id}/schedules')
def list_schedules(asset_id: str):
    return schedule_service.list_for_asset(asset_id)


@router.delete('/schedules/{schedule_id}')
def delete_schedule(schedule_id: str):
    schedule_service.delete(schedule_id)
    return JSONResponse({'deleted': True})


@router.get('/alerts')
def list_alerts(asset_id: str | None = None):
    return scan_service.list_alerts(asset_id)


@router.get('/dashboard')
def dashboard():
    return scan_service.dashboard_summary()


@router.get('/asset-groups')
def asset_groups():
    groups = asset_service.grouped_by_tags()
    return {tag: assets for tag, assets in groups.items()}


# Compare the latest two jobs of the same scan type to highlight added/removed findings.
@router.get('/assets/{asset_id}/compare')
def compare_scans(asset_id: str, scan_type: ScanType = Query(...)):
    return scan_service.compare_latest_two(asset_id, scan_type)


@router.get('/assets/{asset_id}/export.csv')
def export_csv(asset_id: str):
    try:
        asset_service.get(asset_id)
        data = scan_service.export_asset_results_csv(asset_id)
        return Response(content=data, media_type='text/csv', headers={'Content-Disposition': f'attachment; filename="asset-{asset_id}.csv"'})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/assets/{asset_id}/export.pdf')
def export_pdf(asset_id: str):
    try:
        asset = asset_service.get(asset_id)
        data = scan_service.export_asset_results_pdf(asset)
        return Response(content=data, media_type='application/pdf', headers={'Content-Disposition': f'attachment; filename="asset-{asset_id}.pdf"'})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
