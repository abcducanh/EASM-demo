from __future__ import annotations

from app.models.asset import Asset, AssetCreate, AssetType
from app.storage.memory import store


class AssetService:
    def create(self, payload: AssetCreate) -> Asset:
        existing = self.find_by_name_and_type(payload.name, payload.type)
        if existing:
            if payload.tags:
                merged = sorted(set(existing.tags) | set(payload.tags))
                updated = existing.model_copy(update={'tags': merged})
                store.assets[existing.id] = updated
                return updated
            return existing
        asset = Asset(name=payload.name, type=payload.type, tags=payload.tags)
        store.assets[asset.id] = asset
        return asset

    def create_if_missing(self, name: str, asset_type: AssetType, tags: list[str] | None = None) -> Asset:
        existing = self.find_by_name_and_type(name, asset_type)
        if existing:
            return existing
        asset = Asset(name=name, type=asset_type, tags=tags or [])
        store.assets[asset.id] = asset
        return asset

    def update_tags(self, asset_id: str, tags: list[str]) -> Asset:
        asset = self.get(asset_id)
        clean = sorted({tag.strip().lower() for tag in tags if tag and tag.strip()})
        updated = asset.model_copy(update={'tags': clean})
        store.assets[asset.id] = updated
        return updated

    def find_by_name_and_type(self, name: str, asset_type: AssetType) -> Asset | None:
        for asset in store.assets.values():
            if asset.name == name and asset.type == asset_type:
                return asset
        return None

    def list(self) -> list[Asset]:
        return list(store.assets.values())

    def get(self, asset_id: str) -> Asset:
        asset = store.assets.get(asset_id)
        if not asset:
            raise KeyError('asset not found')
        return asset

    def delete(self, asset_id: str) -> None:
        with store.lock:
            if asset_id in store.assets:
                del store.assets[asset_id]
            store.asset_jobs.pop(asset_id, None)
            store.asset_schedules.pop(asset_id, None)

    def delete_all(self) -> None:
        store.reset()

    def tag_summary(self) -> list[dict]:
        counts: dict[str, int] = {}
        for asset in store.assets.values():
            for tag in asset.tags:
                counts[tag] = counts.get(tag, 0) + 1
        return [{'tag': tag, 'count': count} for tag, count in sorted(counts.items())]

    def grouped_by_tags(self) -> dict[str, list[Asset]]:
        groups: dict[str, list[Asset]] = {}
        for asset in self.list():
            for tag in asset.tags:
                groups.setdefault(tag, []).append(asset)
        return groups
