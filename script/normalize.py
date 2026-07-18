#!/usr/bin/env python3
"""Deduplicate catalog entries and normalize samples into .7z archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from catalog import CatalogEntry, catalog_modules, write_json


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def pick_canonical(group: list[dict]) -> dict:
    tipo_rank = {"colecao": 0, "artefato": 1, "referencia": 2}

    def sort_key(entry: dict) -> tuple:
        return (tipo_rank.get(entry["tipo"], 9), len(entry["caminho"]), entry["caminho"])

    return min(group, key=sort_key)


def deduplicate_entries(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        groups[entry["hash"]].append(entry)

    unique: list[dict] = []
    duplicates: list[dict] = []

    for content_hash, group in sorted(groups.items(), key=lambda item: item[0]):
        canonical = pick_canonical(group)
        removed = [item for item in group if item["caminho"] != canonical["caminho"]]

        record = dict(canonical)
        record["hash_conteudo"] = content_hash
        record["origens"] = sorted(item["caminho"] for item in group)
        record["origem_canonica"] = canonical["caminho"]
        record["duplicatas_removidas"] = len(removed)

        if removed:
            duplicates.append(
                {
                    "hash_conteudo": content_hash,
                    "origem_canonica": canonical["caminho"],
                    "removidas": sorted(item["caminho"] for item in removed),
                }
            )

        unique.append(record)

    return unique, duplicates


def resolve_source_path(modules_dir: Path, entry: dict) -> Path:
    return modules_dir / entry["origem_canonica"]


def archive_name(content_hash: str) -> str:
    return f"{content_hash[:16]}.7z"


def create_7z(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()

    command = [
        "7z",
        "a",
        "-t7z",
        "-mx=1",
        "-bd",
        str(destination),
        str(source),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "7z failed")


def build_record(
    index: int,
    entry: dict,
    modules_dir: Path,
    archives_dir: Path,
    skip_archives: bool,
) -> dict:
    record = {
        "id": f"HC-{index:06d}",
        "identificador": entry["identificador"],
        "categoria": entry["categoria"],
        "tipo": entry["tipo"],
        "hash_conteudo": entry["hash_conteudo"],
        "origem_canonica": entry["origem_canonica"],
        "origens": entry["origens"],
        "duplicatas_removidas": entry["duplicatas_removidas"],
        "plataforma": entry["plataforma"],
        "dificuldade": entry["dificuldade"],
        "finalidade": entry["finalidade"],
        "risco": entry["risco"],
        "status": entry["status"],
        "observacoes": entry["observacoes"],
        "repositorio": entry["repositorio"],
        "tamanho_bytes": entry["tamanho_bytes"],
        "contagem_arquivos": entry["contagem_arquivos"],
        "extensao": entry["extensao"],
        "modificado_em": entry["modificado_em"],
        "arquivo": None,
        "hash_arquivo": None,
        "tamanho_arquivo": None,
    }

    if entry["tipo"] == "referencia":
        record["observacoes"] = "Referencia curada; sem arquivo normalizado"
        return record

    source = resolve_source_path(modules_dir, entry)
    if not source.exists():
        record["status"] = "erro_origem_ausente"
        record["observacoes"] = f"Origem nao encontrada: {source}"
        return record

    archive_path = archives_dir / archive_name(entry["hash_conteudo"])
    record["arquivo"] = str(Path("archives") / archive_path.name)

    if skip_archives:
        if archive_path.exists():
            record["hash_arquivo"] = sha256_file(archive_path)
            record["tamanho_arquivo"] = archive_path.stat().st_size
        return record

    if not archive_path.exists():
        create_7z(source, archive_path)

    record["hash_arquivo"] = sha256_file(archive_path)
    record["tamanho_arquivo"] = archive_path.stat().st_size
    return record


def build_summary(
    total_catalogadas: int,
    unique: list[dict],
    duplicates: list[dict],
    records: list[dict],
) -> dict:
    archived = [item for item in records if item["arquivo"]]
    missing = [item for item in records if item["status"] == "erro_origem_ausente"]

    return {
        "total_catalogadas": total_catalogadas,
        "total_unicas": len(unique),
        "total_duplicatas_removidas": total_catalogadas - len(unique),
        "grupos_duplicados": len(duplicates),
        "total_arquivos_7z": len(archived),
        "total_referencias": sum(1 for item in records if item["tipo"] == "referencia"),
        "total_erros": len(missing),
        "bytes_origem": sum(item["tamanho_bytes"] for item in records),
        "bytes_arquivos_7z": sum(item["tamanho_arquivo"] or 0 for item in records),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Normaliza amostras unicas em .7z com metadata.json")
    parser.add_argument("--modules-dir", type=Path, default=root / ".modules")
    parser.add_argument("--output-dir", type=Path, default=root / "dist")
    parser.add_argument("--catalog", type=Path, help="catalog.json existente; se omitido, recataloga")
    parser.add_argument("--limit", type=int, default=0, help="Processa apenas N entradas unicas")
    parser.add_argument("--skip-archives", action="store_true", help="Gera metadata sem criar .7z")
    parser.add_argument("--dry-run", action="store_true", help="Alias para --skip-archives")
    return parser.parse_args(argv)


def load_catalog(args: argparse.Namespace) -> list[dict]:
    if args.catalog:
        payload = json.loads(args.catalog.read_text(encoding="utf-8"))
        return payload["entradas"]

    result = catalog_modules(args.modules_dir.resolve())
    return [asdict(entry) for entry in result.entradas]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    modules_dir = args.modules_dir.resolve()
    output_dir = args.output_dir.resolve()
    archives_dir = output_dir / "archives"
    skip_archives = args.skip_archives or args.dry_run

    if not modules_dir.exists():
        print(f"Erro: diretorio de modulos nao encontrado: {modules_dir}", file=sys.stderr)
        return 1

    print("Carregando catalogo...")
    entries = load_catalog(args)
    unique, duplicates = deduplicate_entries(entries)

    if args.limit:
        unique = unique[: args.limit]

    print(f"Unicas: {len(unique)} | Grupos duplicados: {len(duplicates)}")

    records: list[dict] = []
    for index, entry in enumerate(unique, start=1):
        if index % 50 == 0 or index == 1:
            print(f"Processando {index}/{len(unique)}: {entry['origem_canonica']}")
        records.append(build_record(index, entry, modules_dir, archives_dir, skip_archives))

    metadata = {
        "gerado_em": datetime.now(timezone.utc).isoformat(),
        "modulos_dir": str(modules_dir),
        "formato_arquivo": "7z",
        "resumo": build_summary(len(entries), unique, duplicates, records),
        "amostras": records,
    }

    write_json(output_dir / "metadata.json", metadata)
    write_json(output_dir / "duplicates.json", {"gerado_em": metadata["gerado_em"], "duplicatas": duplicates})

    print(f"metadata.json: {output_dir / 'metadata.json'}")
    print(f"Arquivos .7z: {metadata['resumo']['total_arquivos_7z']}")
    print(f"Duplicatas removidas: {metadata['resumo']['total_duplicatas_removidas']}")
    print(f"Grupos duplicados: {metadata['resumo']['grupos_duplicados']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
