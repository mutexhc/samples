#!/usr/bin/env python3
"""Catalog malware samples from .modules/ into dist/."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

ARTIFACT_EXTENSIONS = frozenset(
    {
        ".7z",
        ".apk",
        ".bat",
        ".bin",
        ".cpl",
        ".dll",
        ".dmg",
        ".doc",
        ".docm",
        ".elf",
        ".exe",
        ".hta",
        ".jar",
        ".js",
        ".msi",
        ".pdf",
        ".ps1",
        ".rar",
        ".scr",
        ".so",
        ".tar",
        ".vbs",
        ".zip",
    }
)

SKIP_DIR_NAMES = frozenset({".git", ".svn", "__pycache__", "node_modules"})
SOURCE_EXTENSIONS = frozenset({".c", ".cpp", ".h", ".hpp", ".asm", ".py", ".php", ".java", ".go", ".rs", ".rb", ".pl", ".cs", ".m", ".swift"})

SOURCE_REPOS = {
    "vxunderground": "https://github.com/vxunderground/MalwareSourceCode",
    "objective-see": "https://github.com/objective-see/Malware",
    "RamadhanAmizudin": "https://github.com/RamadhanAmizudin/malware",
    "RPISEC": "https://github.com/RPISEC/Malware",
    "gbrindisi": "https://github.com/gbrindisi/malware",
    "Endermanch": "https://github.com/Endermanch/MalwareDatabase",
    "rshipp": "https://github.com/rshipp/awesome-malware-analysis",
}

PLATFORM_HINTS = {
    "android": "Android",
    "linux": "Linux",
    "macos": "macOS",
    "win32": "Windows",
    "windows": "Windows",
    "ios": "iOS",
    "php": "PHP",
    "python": "Python",
    "java": "Java",
    "javascript": "JavaScript",
    "perl": "Perl",
    "ruby": "Ruby",
    "msdos": "MS-DOS",
    "legacywindows": "Legacy Windows",
    "panel": "Web Panel",
    "phishing": "Phishing",
    "pointofsales": "Point of Sale",
    "engines": "Multi-platform",
    "other": "Other",
}

EXTENSION_PLATFORM = {
    ".exe": "Windows",
    ".dll": "Windows",
    ".scr": "Windows",
    ".cpl": "Windows",
    ".msi": "Windows",
    ".hta": "Windows",
    ".vbs": "Windows",
    ".bat": "Windows",
    ".ps1": "Windows",
    ".elf": "Linux",
    ".so": "Linux",
    ".apk": "Android",
    ".dmg": "macOS",
    ".jar": "Java",
    ".php": "PHP",
    ".py": "Python",
    ".js": "JavaScript",
    ".rb": "Ruby",
    ".pl": "Perl",
}


@dataclass
class CatalogEntry:
    identificador: str
    categoria: str
    origem: str
    hash: str
    plataforma: str
    dificuldade: str
    finalidade: str
    risco: str
    status: str
    observacoes: str
    tipo: str
    caminho: str
    repositorio: str
    tamanho_bytes: int = 0
    contagem_arquivos: int = 0
    extensao: str = ""
    modificado_em: str = ""


@dataclass
class CatalogResult:
    gerado_em: str
    modulos_dir: str
    entradas: list[CatalogEntry] = field(default_factory=list)
    resumo: dict = field(default_factory=dict)


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "item"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_manifest(paths: Iterator[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: str(item.relative_to(root)).lower()):
        rel = str(path.relative_to(root)).replace("\\", "/")
        stat = path.stat()
        digest.update(f"{rel}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def infer_platform(path: Path, source: str) -> str:
    parts = {part.lower() for part in path.parts}
    for hint, platform in PLATFORM_HINTS.items():
        if hint in parts:
            return platform

    ext = path.suffix.lower()
    if ext in EXTENSION_PLATFORM:
        return EXTENSION_PLATFORM[ext]

    if source == "objective-see":
        return "macOS"
    if source == "rshipp":
        return "Referencia"
    if source == "RPISEC":
        return "Multi-platform"
    return "Desconhecida"


def infer_finalidade(name: str, entry_type: str, platform: str) -> str:
    lowered = name.lower()
    if entry_type == "referencia":
        return "Curadoria de recursos para analise de malware"
    if entry_type == "colecao":
        if "lab" in lowered:
            return "Laboratorio de analise de malware"
        if "lecture" in lowered or "project" in lowered:
            return "Material didatico de engenharia reversa"
        return "Estudo de familia, variante ou codigo-fonte"
    if entry_type == "artefato":
        if platform in {"Web Panel", "Phishing", "PHP"}:
            return "Analise de painel, web shell ou phishing"
        return "Triagem, hash e analise estatica"
    return "Pesquisa em ambiente controlado"


def infer_risco(entry_type: str, path: Path, size_bytes: int) -> str:
    if entry_type == "referencia":
        return "baixo"
    ext = path.suffix.lower()
    if entry_type == "artefato" and ext in ARTIFACT_EXTENSIONS:
        if ext in {".exe", ".dll", ".scr", ".msi", ".hta", ".vbs", ".bat", ".ps1", ".apk", ".dmg"}:
            return "restrito"
        return "alto"
    if entry_type == "colecao":
        if size_bytes > 100 * 1024 * 1024:
            return "restrito"
        return "moderado"
    return "baixo"


def infer_dificuldade(source: str, name: str, entry_type: str) -> str:
    lowered = name.lower()
    if source == "RPISEC" and entry_type == "colecao":
        if "lab" in lowered:
            return "intermediario"
        return "introdutorio"
    if source == "rshipp":
        return "introdutorio"
    if entry_type == "artefato":
        return "intermediario"
    return "avancado"


def make_id(source: str, *parts: str) -> str:
    return slugify("-".join([source, *parts]))


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIR_NAMES for part in path.parts)


def iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not should_skip(path):
            yield path


def relative_module_path(path: Path, modules_dir: Path) -> Path:
    return path.relative_to(modules_dir)


def collection_roots(source: str, repo_root: Path) -> list[Path]:
    if source == "RamadhanAmizudin":
        malware_dir = repo_root / "malware"
        return sorted(
            child for child in malware_dir.iterdir() if child.is_dir() and child.name not in SKIP_DIR_NAMES
        )

    if source == "objective-see":
        malware_dir = repo_root / "Malware"
        return sorted(child for child in malware_dir.iterdir() if child.is_file() and child.suffix.lower() == ".zip")

    if source == "RPISEC":
        malware_dir = repo_root / "Malware"
        roots: list[Path] = []
        for section in ("Labs", "Projects", "Lectures", "resources"):
            section_dir = malware_dir / section
            if not section_dir.exists():
                continue
            if section == "resources":
                roots.append(section_dir)
            else:
                roots.extend(sorted(child for child in section_dir.iterdir() if child.is_dir()))
        return roots

    if source == "gbrindisi":
        malware_dir = repo_root / "malware"
        roots = []
        for platform_dir in sorted(malware_dir.iterdir()):
            if not platform_dir.is_dir() or platform_dir.name in SKIP_DIR_NAMES:
                continue
            children = [child for child in platform_dir.iterdir() if child.is_dir()]
            if children:
                roots.extend(children)
            else:
                roots.append(platform_dir)
        return roots

    if source == "Endermanch":
        db_dir = repo_root / "MalwareDatabase"
        roots = []
        for child in sorted(db_dir.iterdir()):
            if child.name in SKIP_DIR_NAMES or child.name == "README.md":
                continue
            if child.is_file() and child.suffix.lower() in ARTIFACT_EXTENSIONS:
                roots.append(child)
            elif child.is_dir():
                roots.append(child)
        return roots

    if source == "rshipp":
        return [repo_root / "awesome-malware-analysis"]

    return []


def catalog_vxunderground(repo_root: Path, modules_dir: Path) -> list[CatalogEntry]:
    entries: list[CatalogEntry] = []
    source = "vxunderground"
    repo = SOURCE_REPOS[source]
    code_dir = repo_root / "MalwareSourceCode"
    catalogable = ARTIFACT_EXTENSIONS | SOURCE_EXTENSIONS

    for path in sorted(iter_files(code_dir)):
        ext = path.suffix.lower()
        if ext not in catalogable:
            continue

        rel = relative_module_path(path, modules_dir)
        stat = path.stat()
        platform = infer_platform(path, source)
        rel_key = str(path.relative_to(code_dir)).replace("/", "-").replace(".", "-")

        entries.append(
            CatalogEntry(
                identificador=make_id(source, rel_key),
                categoria="malware",
                origem=str(rel),
                hash=sha256_file(path),
                plataforma=platform,
                dificuldade=infer_dificuldade(source, path.name, "artefato"),
                finalidade=infer_finalidade(path.name, "artefato", platform),
                risco=infer_risco("artefato", path, stat.st_size),
                status="em_triagem",
                observacoes=f"Artefato vx-underground ({ext or 'sem extensao'})",
                tipo="artefato",
                caminho=str(rel),
                repositorio=repo,
                tamanho_bytes=stat.st_size,
                contagem_arquivos=1,
                extensao=ext,
                modificado_em=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            )
        )

    return entries


def catalog_collection(source: str, collection_path: Path, modules_dir: Path) -> CatalogEntry:
    repo = SOURCE_REPOS[source]
    rel = relative_module_path(collection_path, modules_dir)
    files = list(iter_files(collection_path)) if collection_path.is_dir() else []
    stat = collection_path.stat()
    platform = infer_platform(collection_path, source)
    entry_type = "referencia" if source == "rshipp" else ("artefato" if collection_path.is_file() else "colecao")
    size_bytes = stat.st_size if collection_path.is_file() else sum(item.stat().st_size for item in files)
    file_hash = sha256_file(collection_path) if collection_path.is_file() else sha256_manifest(files, collection_path)

    rel_key = str(rel).replace("/", "-").replace(".", "-")

    return CatalogEntry(
        identificador=make_id(source, rel_key),
        categoria="malware" if source != "rshipp" else "referencia",
        origem=str(rel),
        hash=file_hash,
        plataforma=platform,
        dificuldade=infer_dificuldade(source, collection_path.name, entry_type),
        finalidade=infer_finalidade(collection_path.name, entry_type, platform),
        risco=infer_risco(entry_type, collection_path, size_bytes),
        status="em_triagem",
        observacoes=(
            "Lista curada de recursos para analise de malware"
            if source == "rshipp"
            else f"Coleção {collection_path.name} de {source}"
        ),
        tipo=entry_type,
        caminho=str(rel),
        repositorio=repo,
        tamanho_bytes=size_bytes,
        contagem_arquivos=len(files) if collection_path.is_dir() else 1,
        extensao=collection_path.suffix.lower(),
        modificado_em=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    )


def build_summary(entries: list[CatalogEntry]) -> dict:
    by_source: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    by_platform: Counter[str] = Counter()
    by_risk: Counter[str] = Counter()
    total_bytes = 0

    for entry in entries:
        source = entry.caminho.split("/", 1)[0]
        by_source[source] += 1
        by_type[entry.tipo] += 1
        by_platform[entry.plataforma] += 1
        by_risk[entry.risco] += 1
        total_bytes += entry.tamanho_bytes

    return {
        "total_entradas": len(entries),
        "total_bytes": total_bytes,
        "por_modulo": dict(sorted(by_source.items())),
        "por_tipo": dict(sorted(by_type.items())),
        "por_plataforma": dict(sorted(by_platform.items())),
        "por_risco": dict(sorted(by_risk.items())),
    }


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def write_csv(path: Path, entries: list[CatalogEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(asdict(entries[0]).keys()) if entries else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(asdict(entry))


def catalog_modules(modules_dir: Path) -> CatalogResult:
    entries: list[CatalogEntry] = []

    for source_dir in sorted(modules_dir.iterdir()):
        if not source_dir.is_dir() or source_dir.name.startswith("."):
            continue

        source = source_dir.name
        if source == "vxunderground":
            entries.extend(catalog_vxunderground(source_dir, modules_dir))
            continue

        for root in collection_roots(source, source_dir):
            entries.append(catalog_collection(source, root, modules_dir))

    entries.sort(key=lambda item: (item.caminho, item.tipo))
    return CatalogResult(
        gerado_em=datetime.now(timezone.utc).isoformat(),
        modulos_dir=str(modules_dir),
        entradas=entries,
        resumo=build_summary(entries),
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cataloga amostras de malware em .modules/")
    parser.add_argument(
        "--modules-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / ".modules",
        help="Diretorio com os repositorios clonados",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "dist",
        help="Diretorio de saida do catalogo",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    modules_dir = args.modules_dir.resolve()
    output_dir = args.output_dir.resolve()

    if not modules_dir.exists():
        print(f"Erro: diretorio de modulos nao encontrado: {modules_dir}", file=sys.stderr)
        return 1

    print(f"Catalogando {modules_dir} ...")
    result = catalog_modules(modules_dir)

    catalog_payload = {
        "gerado_em": result.gerado_em,
        "resumo": result.resumo,
        "entradas": [asdict(entry) for entry in result.entradas],
    }

    write_json(output_dir / "catalog.json", catalog_payload)
    write_json(output_dir / "summary.json", {"gerado_em": result.gerado_em, "resumo": result.resumo})
    write_csv(output_dir / "catalog.csv", result.entradas)

    print(f"Entradas: {result.resumo['total_entradas']}")
    print(f"Tamanho total: {result.resumo['total_bytes']:,} bytes")
    print(f"JSON: {output_dir / 'catalog.json'}")
    print(f"CSV:  {output_dir / 'catalog.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
