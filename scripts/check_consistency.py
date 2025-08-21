#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BottleBalance Konsistenz-Check

Prüft:
- Blueprints: Definitionen, Nutzungen (@bp.route/get/post/...), Registrierung in web/app.py
- Interne Imports: from modules.<name> -> web/modules/<name>.py vorhanden?
- Top-Level-Module: from <name> import ... -> web/<name>.py vorhanden?
- Templates: render_template('...') -> Datei existiert unter web/templates/
- Doppelte Funktionsnamen (Hinweis)
- AST-Parsefehler (harte Fehler)
- Saubere Zusammenfassung; Warnung wenn 0 Dateien gescannt

Aufrufbeispiele:
  python check_consistency.py
  python check_consistency.py --root .
  python check_consistency.py --json report.json
  python scripts/check_consistency.py --root /var/lib/docker/volumes/bottlebalance-dev

"""

from __future__ import annotations
import argparse
import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional
import json
import sys

# --------------------------- Datenmodelle ---------------------------

@dataclass
class BlueprintDef:
    var: str                # Variablenname (z.B. payment_routes)
    name: str               # Blueprint-Name im Konstruktor
    file: Path              # Datei der Definition

@dataclass
class FileReport:
    path: Path
    blueprints_defined: Dict[str, BlueprintDef] = field(default_factory=dict)
    blueprints_used: Set[str] = field(default_factory=set)
    functions_defined: Set[str] = field(default_factory=set)
    imports_internal_modules: Set[str] = field(default_factory=set)  # modules.<name>
    imports_top_modules: Set[str] = field(default_factory=set)       # e.g. auth, bbalance
    templates_referenced: Set[str] = field(default_factory=set)
    parse_error: Optional[str] = None

@dataclass
class AppRegistration:
    file: Path
    blueprints_registered: List[str] = field(default_factory=list)   # Variablennamen

@dataclass
class ProjectReport:
    files: List[FileReport]
    app_reg: Optional[AppRegistration]
    problems: Dict[str, List[str]]
    duplicates: Dict[str, List[str]]
    summary: Dict[str, int]

# --------------------------- AST Visitors ---------------------------

class ModuleAnalyzer(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.report = FileReport(path=path)

    def visit_Assign(self, node: ast.Assign):
        # <var> = Blueprint('name', __name__)
        try:
            if isinstance(node.value, ast.Call):
                call = node.value
                func_name = None
                if isinstance(call.func, ast.Name):
                    func_name = call.func.id
                elif isinstance(call.func, ast.Attribute):
                    func_name = call.func.attr
                if func_name == "Blueprint" and call.args:
                    if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                        bp_name = call.args[0].value
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                var = t.id
                                self.report.blueprints_defined[var] = BlueprintDef(
                                    var=var, name=bp_name, file=self.path
                                )
        finally:
            self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Funktionen auf Modulebene
        self.report.functions_defined.add(node.name)

        # Dekoratoren nach Blueprint-Nutzung: @<bp>.<route>/<get>/<post>...
        for dec in node.decorator_list:
            # @bp.route('/..')  oder  @bp.get('/..')
            if isinstance(dec, ast.Attribute) and isinstance(dec.value, ast.Name):
                self.report.blueprints_used.add(dec.value.id)
            # @bp.route(...) als Call
            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and isinstance(dec.func.value, ast.Name):
                self.report.blueprints_used.add(dec.func.value.id)

        # render_template('xyz.html') im Funktionskörper
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func = call.func
                if isinstance(func, ast.Name) and func.id == "render_template":
                    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                        self.report.templates_referenced.add(call.args[0].value)
                elif isinstance(func, ast.Attribute) and func.attr == "render_template":
                    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                        self.report.templates_referenced.add(call.args[0].value)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # render_template() auch auf Modulebene (falls vorhanden)
        func = node.func
        if isinstance(func, ast.Name) and func.id == "render_template":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.report.templates_referenced.add(node.args[0].value)
        elif isinstance(func, ast.Attribute) and func.attr == "render_template":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.report.templates_referenced.add(node.args[0].value)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # from modules.foo import bar  → foo in web/modules/foo.py?
        if node.module and node.module.startswith("modules."):
            parts = node.module.split(".")
            if len(parts) >= 2:
                self.report.imports_internal_modules.add(parts[1])
        else:
            # from auth import auth_routes → web/auth.py?
            if node.module and "." not in node.module:
                self.report.imports_top_modules.add(node.module)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            if name.startswith("modules."):
                parts = name.split(".")
                if len(parts) >= 2:
                    self.report.imports_internal_modules.add(parts[1])
            elif "." not in name:
                self.report.imports_top_modules.add(name)
        self.generic_visit(node)

class AppRegistrationAnalyzer(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.reg = AppRegistration(file=path)

    @staticmethod
    def _rightmost_attr(n: ast.AST) -> Optional[str]:
        # auth.auth_routes → "auth_routes"
        cur = n
        last = None
        while isinstance(cur, ast.Attribute):
            last = cur.attr if isinstance(cur.attr, str) else None
            cur = cur.value
        if isinstance(cur, ast.Name):
            # z. B. bp_var.attr → last bleibt attr
            return last or cur.id
        return last

    def visit_Call(self, node: ast.Call):
        try:
            if isinstance(node.func, ast.Attribute) and node.func.attr == "register_blueprint":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name):
                        self.reg.blueprints_registered.append(arg.id)
                    elif isinstance(arg, ast.Attribute):
                        rn = self._rightmost_attr(arg)
                        if rn:
                            self.reg.blueprints_registered.append(rn)
        finally:
            self.generic_visit(node)

# --------------------------- Scanner / Logik ---------------------------

def find_repo_root(cli_root: Optional[str]) -> Path:
    if cli_root:
        return Path(cli_root).resolve()
    here = Path(__file__).resolve()
    # Wenn Skript in scripts/ liegt → Repo-Root = parent of parent
    if here.parent.name == "scripts":
        return here.parent.parent
    # sonst: aktuelles Verzeichnis
    return here.parent

def collect_python_files(web_dir: Path) -> List[Path]:
    return [p for p in web_dir.rglob("*.py") if "__pycache__" not in p.parts]

def analyze_file(path: Path) -> FileReport:
    try:
        src = path.read_text(encoding="utf-8")
    except Exception as e:
        fr = FileReport(path=path, parse_error=f"Lesefehler: {e}")
        return fr
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return FileReport(path=path, parse_error=f"SyntaxError: {e}")
    analyzer = ModuleAnalyzer(path)
    analyzer.visit(tree)
    return analyzer.report

def analyze_app_registration(app_path: Path) -> Optional[AppRegistration]:
    if not app_path.exists():
        return None
    try:
        tree = ast.parse(app_path.read_text(encoding="utf-8"), filename=str(app_path))
    except SyntaxError:
        return None
    ar = AppRegistrationAnalyzer(app_path)
    ar.visit(tree)
    return ar.reg

def build_report(root: Path, json_out: Optional[Path]) -> ProjectReport:
    web_dir = root / "web"
    modules_dir = web_dir / "modules"
    templates_dir = web_dir / "templates"
    app_path = web_dir / "app.py"

    problems: Dict[str, List[str]] = {
        "no_python_files_found": [],
        "blueprint_used_not_defined": [],
        "blueprint_defined_not_registered": [],
        "registration_unknown_blueprint": [],
        "missing_internal_module": [],
        "missing_top_module": [],
        "missing_template": [],
        "parse_errors": [],
    }

    if not web_dir.exists():
        problems["no_python_files_found"].append(
            f"Erwarteter Ordner 'web/' fehlt unter Root: {root}"
        )
        return ProjectReport(
            files=[], app_reg=None, problems=problems, duplicates={}, summary={"files_scanned": 0}
        )

    files = collect_python_files(web_dir)
    if not files:
        problems["no_python_files_found"].append(
            f"Keine Python-Dateien unter {web_dir} gefunden."
        )
        return ProjectReport(
            files=[], app_reg=None, problems=problems, duplicates={}, summary={"files_scanned": 0}
        )

    file_reports: List[FileReport] = [analyze_file(p) for p in files]

    # Aggregation
    bp_defs_all: Dict[str, BlueprintDef] = {}
    bp_used_all: Dict[str, Set[str]] = {}
    func_defs_map: Dict[str, List[str]] = {}

    for fr in file_reports:
        if fr.parse_error:
            problems["parse_errors"].append(f"{fr.path.relative_to(root)}: {fr.parse_error}")
            continue
        for var, bp in fr.blueprints_defined.items():
            bp_defs_all[var] = bp
        for var in fr.blueprints_used:
            bp_used_all.setdefault(var, set()).add(str(fr.path.relative_to(root)))
        for fn in fr.functions_defined:
            func_defs_map.setdefault(fn, []).append(str(fr.path.relative_to(root)))

    app_reg = analyze_app_registration(app_path)
    registered_vars: Set[str] = set(app_reg.blueprints_registered) if app_reg else set()

    
    # Blueprints: genutzt aber nicht definiert
    # Ignoriere bekannte Nicht-Blueprints (z. B. Flask-App-Instanz 'app')
    ignore_non_blueprints = {"app"}
    for used_var, used_in in bp_used_all.items():
        if used_var in ignore_non_blueprints:
            continue
        if used_var not in bp_defs_all:
            problems["blueprint_used_not_defined"].append(
                f"Blueprint-Variable '{used_var}' wird verwendet in: {', '.join(sorted(used_in))}, aber nirgends definiert."
            )

    # Blueprints: definiert aber nicht registriert
    for var, bp in bp_defs_all.items():
        if var not in registered_vars:
            problems["blueprint_defined_not_registered"].append(
                f"Blueprint '{bp.name}' ({var}) definiert in {bp.file.relative_to(root)} ist NICHT in web/app.py registriert."
            )

    # Registrierungen auf unbekannte Variablen
    if app_reg:
        for var in app_reg.blueprints_registered:
            if var not in bp_defs_all:
                problems["registration_unknown_blueprint"].append(
                    f"web/app.py registriert '{var}', aber es gibt keine entsprechende Blueprint-Variable in den Modulen."
                )

    # Interne Imports: modules.*
    internal_modules = {p.stem for p in modules_dir.glob("*.py")}
    top_modules = {p.stem for p in web_dir.glob("*.py")}  # alle top-level .py unter web/

    
    stdlib_common = {
        "os", "sys", "re", "json", "typing", "argparse", "pathlib", "ast",
        "secrets", "base64", "subprocess", "logging", "datetime", "decimal",
        "uuid", "time", "csv", "io",
        # ergänzt für dein Projekt
        "ssl", "types", "mimetypes", "functools", "smtplib"
    }
    third_party_common = {
        "flask", "flask_babel", "sqlalchemy", "werkzeug", "reportlab", "pyotp", "qrcode",
        # ergänzt
        "flask_mail"
    }


    for fr in file_reports:
        for m in fr.imports_internal_modules:
            if m not in internal_modules:
                problems["missing_internal_module"].append(
                    f"{fr.path.relative_to(root)}: 'from modules.{m} import ...' – web/modules/{m}.py fehlt."
                )

        for tm in fr.imports_top_modules:
            # ignoriere häufige stdlib/3rd-party imports
            if tm in stdlib_common or tm in third_party_common:
                continue
            candidates = {tm, tm.replace("-", "_")}
            if not any((web_dir / f"{c}.py").exists() for c in candidates):
                problems["missing_top_module"].append(
                    f"{fr.path.relative_to(root)}: 'from {tm} import ...' – erwartet web/{tm}.py (oder {tm.replace('-', '_')}.py)."
                )

        for tpl in fr.templates_referenced:
            if not (templates_dir / tpl).exists():
                problems["missing_template"].append(
                    f"{fr.path.relative_to(root)}: Template '{tpl}' nicht gefunden unter web/templates/."
                )

    duplicates = {fn: paths for fn, paths in func_defs_map.items() if len(paths) > 1}

    summary = {
        "files_scanned": len(files),
        "blueprints_defined": len(bp_defs_all),
        "blueprints_used": sum(len(v) for v in bp_used_all.values()),
        "blueprints_registered": len(registered_vars),
        "problems_total": sum(len(v) for v in problems.values()),
        "duplicates_functions": len(duplicates),
    }

    if json_out:
        json_out.write_text(json.dumps({
            "summary": summary,
            "problems": problems,
            "duplicates": duplicates,
            "blueprints_registered": sorted(registered_vars),
        }, indent=2, ensure_ascii=False), encoding="utf-8")

    return ProjectReport(
        files=file_reports, app_reg=app_reg, problems=problems,
        duplicates=duplicates, summary=summary
    )

# --------------------------- CLI ---------------------------

def main():
    ap = argparse.ArgumentParser(description="BottleBalance Konsistenz-Check")
    ap.add_argument("--root", help="Repo-Root (Standard: auto)", default=None)
    ap.add_argument("--json", help="Optional: Ergebnisse als JSON exportieren", default=None)
    args = ap.parse_args()

    root = find_repo_root(args.root)
    json_out = Path(args.json).resolve() if args.json else None

    report = build_report(root, json_out)

    print("🔍 Starte Konsistenz-Check...\n")
    print("📁 Root:", root)
    print("🔎 Zusammenfassung:", json.dumps(report.summary, indent=2, ensure_ascii=False))

    def dump(title: str, items: List[str]):
        if items:
            print(f"\n⚠️  {title} ({len(items)}):")
            for it in items:
                print("   -", it)
        else:
            print(f"\n✅ {title}: keine Probleme")

    dump("Kein Python-Code gefunden", report.problems.get("no_python_files_found", []))
    dump("Blueprint genutzt aber nicht definiert", report.problems.get("blueprint_used_not_defined", []))
    dump("Blueprint definiert aber nicht registriert", report.problems.get("blueprint_defined_not_registered", []))
    dump("Registrierung verweist auf unbekannte Blueprint-Variable", report.problems.get("registration_unknown_blueprint", []))
    dump("Interner Import (modules.*) fehlt", report.problems.get("missing_internal_module", []))
    dump("Top-Level Modul fehlt (erwartet web/<name>.py)", report.problems.get("missing_top_module", []))
    dump("Fehlende Templates", report.problems.get("missing_template", []))
    dump("Parse-Fehler", report.problems.get("parse_errors", []))

    if report.duplicates:
        print("\n🟨 Potenziell doppelte Funktionsnamen (Hinweis):")
        for fn, paths in sorted(report.duplicates.items()):
            print(f"   - {fn}: {', '.join(paths)}")
    else:
        print("\n✅ Keine doppelten Funktionsnamen auf Modulebene gefunden")

    # Harte Fehler → Exitcode 1 (für CI nutzbar)
    hard_errors = any([
        report.problems.get("no_python_files_found"),
        report.problems.get("blueprint_used_not_defined"),
        report.problems.get("registration_unknown_blueprint"),
        report.problems.get("missing_internal_module"),
        report.problems.get("missing_top_module"),
        report.problems.get("parse_errors"),
    ])
    return 1 if hard_errors else 0

if __name__ == "__main__":
    sys.exit(main())