import yaml
import sys
from datetime import datetime

class GitLabPipelineAuditor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.findings = []
        self.pipeline_data = self._load_yaml()

    def _load_yaml(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file)
        except Exception as e:
            print(f"Error crítico: {e}")
            sys.exit(1)

    def run_audit(self):
        if not self.pipeline_data: return []
        self.check_immutable_images()
        self.check_mandatory_security_tools()
        self.check_security_gates()
        self.check_hardcoded_secrets()
        self.check_advanced_policies()
        self.check_allow_failure()
        self.check_unverified_scripts()
        self.check_trusted_registries()
        return self.findings

    def _add_finding(self, loc, issue, severity, msg):
        self.findings.append({"loc": loc, "issue": issue, "severity": severity, "msg": msg})

    # (Las funciones de check_... se mantienen igual que en la versión anterior)
    def check_immutable_images(self):
        variables = self.pipeline_data.get('variables', {})
        if isinstance(variables, dict):
            for n, v in variables.items():
                if any(k in n.upper() for k in ['TAG', 'IMAGE', 'DIGEST']):
                    if isinstance(v, str) and ':' in v and '@sha256:' not in v:
                        self._add_finding(f"Var: {n}", "Etiqueta Mutable", "MEDIUM", f"Tag: {v}")
        
        global_img = self.pipeline_data.get('image')
        if global_img and '@sha256:' not in str(global_img):
            self._add_finding("Global", "Imagen no inmutable", "CRITICAL", f"Imagen '{global_img}' sin Digest.")

    def check_mandatory_security_tools(self):
        raw = str(self.pipeline_data).lower()
        tools = {"Bandit": "SAST", "Trivy": "SCA", "Cosign": "Firma", "Syft": "SBOM"}
        for t, d in tools.items():
            if t.lower() not in raw:
                self._add_finding("Definición", f"Falta {t}", "HIGH", f"No se detectó {t} para {d}.")

    def check_security_gates(self):
        for job, config in self.pipeline_data.items():
            if isinstance(config, dict) and 'script' in config:
                script = str(config['script']).lower()
                if any(t in script for t in ['trivy', 'bandit', 'grype']) and '$lastexitcode' not in script:
                    self._add_finding(job, "Sin Security Gate", "HIGH", "No gestiona $LASTEXITCODE.")

    def check_hardcoded_secrets(self):
        vars = self.pipeline_data.get('variables', {})
        if not isinstance(vars, dict): return
        keys = ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'AUTH']
        for n, v in vars.items():
            if any(k in n.upper() for k in keys) and isinstance(v, str) and not v.startswith('$'):
                self._add_finding(f"Variable: {n}", "Secreto Expuesto", "CRITICAL", "Contraseña en texto plano.")

    def check_advanced_policies(self):
        for job, config in self.pipeline_data.items():
            if not isinstance(config, dict): continue
            script = str(config.get('script', [])).lower()
            if script and '$erroractionpreference = "stop"' not in script:
                self._add_finding(job, "Política Insegura", "MEDIUM", "Falta '$ErrorActionPreference = Stop'.")
            if config.get('artifacts') and 'expire_in' not in config.get('artifacts'):
                self._add_finding(job, "Artefacto sin Expiración", "LOW", "Falta 'expire_in'.")
    
    def check_allow_failure(self):
        for job, config in self.pipeline_data.items():
            if isinstance(config, dict) and config.get('allow_failure') is True:
                self._add_finding(
                    job, 
                    "Evasión de Fallos (allow_failure)", 
                    "CRITICAL", 
                    "Contiene 'allow_failure: true'. GitLab ignorará los errores y anulará el Security Gate."
                )
    
    def check_unverified_scripts(self):
        for job, config in self.pipeline_data.items():
            if isinstance(config, dict):
                scripts = []
                if 'script' in config:
                    scripts.extend(config['script'] if isinstance(config['script'], list) else [config['script']])
                if 'before_script' in config:
                    scripts.extend(config['before_script'] if isinstance(config['before_script'], list) else [config['before_script']])
                
                for line in scripts:
                    line_str = str(line).lower()
                    # Detecta "curl ... | bash" o "wget ... | sh"
                    if ('curl ' in line_str or 'wget ' in line_str) and ('| bash' in line_str or '| sh' in line_str):
                        self._add_finding(
                            job, 
                            "Ejecución de Script Externo", 
                            "HIGH", 
                            "Descarga y ejecución al vuelo (Piping to shell) detectada. Riesgo masivo de Supply Chain si la URL es comprometida."
                        )

    def check_trusted_registries(self):
        # Define aquí los registros que consideras seguros para tu empresa/proyecto
        trusted_prefixes = ['registry.gitlab.com', 'gcr.io', 'quay.io'] 
        
        # Función auxiliar para comprobar una imagen
        def verificar_imagen(img, loc):
            img_name = str(img.get('name', img) if isinstance(img, dict) else img)
            # Ignoramos si es un servicio de docker-in-docker común
            if "docker:" in img_name: return
            if not any(img_name.startswith(prefix) for prefix in trusted_prefixes):
                self._add_finding(
                    loc, 
                    "Registro No Confiable", 
                    "MEDIUM", 
                    f"Imagen base '{img_name}' descargada de registro público sin proxy de seguridad."
                )

        # Revisar imagen global
        if self.pipeline_data.get('image'):
            verificar_imagen(self.pipeline_data['image'], "Global")
                
        # Revisar imágenes de cada trabajo
        for job, config in self.pipeline_data.items():
            if isinstance(config, dict) and 'image' in config:
                verificar_imagen(config['image'], job)

    def export_as_html(self, template_file="template.html", output_file="reporte_auditoria.html"):
        try:
            with open(template_file, "r", encoding="utf-8") as f:
                html_content = f.read()
        except FileNotFoundError:
            print(f"Error: Crea el archivo {template_file} en esta carpeta.")
            return

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        rows_html = ""
        
        for f in self.findings:
            sev = f['severity']
            counts[sev] += 1
            rows_html += f"""
            <tr data-severity="{sev}">
                <td><span class="badge badge-{sev.lower()}">{sev}</span></td>
                <td><code>{f['loc']}</code></td>
                <td>{f['issue']}</td>
                <td>{f['msg']}</td>
            </tr>
            """

        replacements = {
            "{{FILENAME}}": self.file_path,
            "{{DATE}}": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            "{{C_COUNT}}": str(counts['CRITICAL']),
            "{{H_COUNT}}": str(counts['HIGH']),
            "{{M_COUNT}}": str(counts['MEDIUM']),
            "{{L_COUNT}}": str(counts['LOW']),
            "{{ROWS}}": rows_html if rows_html else '<tr><td colspan="4" style="text-align:center;">¡Felicidades! No se detectaron vulnerabilidades.</td></tr>'
        }

        for placeholder, value in replacements.items():
            html_content = html_content.replace(placeholder, value)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Reporte interactivo generado en: {output_file}")
        
        if counts['CRITICAL'] > 0 or counts['HIGH'] > 0:
            print("\n[!] SECURITY GATE: Se han detectado vulnerabilidades CRÍTICAS o ALTAS en la configuración.")
            print("[!] Abortando el pipeline inmediatamente (Fail-Fast).")
            sys.exit(1) # Esto le dice a GitLab que el Job ha fallado

if __name__ == "__main__":
    auditor = GitLabPipelineAuditor(".gitlab-ci.yml")
    auditor.run_audit()
    auditor.export_as_html()
