#!/usr/bin/env python3
"""Prototipo académico: normalización OFFLINE, triage, revisión y reporte OWASP 2025.
No ejecuta pruebas activas ni explota vulnerabilidades. Sólo procesa archivos locales.
"""
import argparse
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import urllib.request

CATS={
 'A01':'Broken Access Control', 'A02':'Security Misconfiguration',
 'A03':'Software Supply Chain Failures','A04':'Cryptographic Failures',
 'A05':'Injection','A06':'Insecure Design','A07':'Authentication Failures',
 'A08':'Software or Data Integrity Failures','A09':'Security Logging and Alerting Failures',
 'A10':'Mishandling of Exceptional Conditions',
}
CWE_TO_CAT={
 '22':'A01','23':'A01','35':'A01','200':'A01','284':'A01','285':'A01','639':'A01','918':'A01',
 '16':'A02','489':'A02','614':'A02','693':'A02','1021':'A02','1004':'A02',
 '1104':'A03','829':'A03','494':'A03','353':'A03',
 '295':'A04','319':'A04','326':'A04','327':'A04','328':'A04','798':'A04',
 '20':'A05','74':'A05','77':'A05','78':'A05','79':'A05','89':'A05','90':'A05','94':'A05',
 '501':'A06','602':'A06','656':'A06',
 '287':'A07','307':'A07','306':'A07','384':'A07','613':'A07',
 '345':'A08','347':'A08','353':'A08','502':'A08',
 '117':'A09','223':'A09','532':'A09','778':'A09',
 '209':'A10','390':'A10','391':'A10','703':'A10','754':'A10',
}
REMEDIATION={
 'A01':'Validar permisos por recurso en el servidor y ensayar con múltiples roles.',
 'A02':'Aplicar hardening, gestionar cabeceras, eliminar datos de depuración y revisar configuración.',
 'A03':'Inventariar dependencias (SBOM), comprobar procedencia, versiones y CI/CD.',
 'A04':'Revisar TLS, protección de secretos y algoritmos criptográficos.',
 'A05':'Usar consultas parametrizadas, escape contextual y validación de entradas.',
 'A06':'Revisar amenazas, abuso de flujos y restricciones de negocio mediante modelado.',
 'A07':'Revisar MFA, sesiones, bloqueo de intentos y recuperación de credenciales.',
 'A08':'Verificar firmas, checksums y límites de confianza de objetos y artefactos.',
 'A09':'Registrar eventos relevantes, alertar y comprobar retención/monitoreo.',
 'A10':'Tratar errores sin divulgar información ni fallar en modo permisivo.',
}

def sha256_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def cat_for(*terms):
    for t in terms:
        s=str(t or '')
        direct=re.search(r'\b(A(?:0[1-9]|10))(?::2025)?\b',s,re.I)
        if direct:return direct.group(1).upper()
        cwe=re.search(r'CWE[- ]?(\d+)',s,re.I)
        if cwe and cwe.group(1) in CWE_TO_CAT:return CWE_TO_CAT[cwe.group(1)]
    s=' '.join(str(x or '') for x in terms).lower()
    heuristics=[('A05',['sql injection','cross-site scripting','xss','command injection','code injection']),
                ('A01',['access control','idor','path traversal','directory traversal','authorization']),
                ('A02',['header','csp','cookie without','misconfiguration','server leaks','server header']),
                ('A03',['vulnerable component','dependency','supply chain']),
                ('A04',['encryption','tls','weak cipher','cryptographic']),
                ('A07',['authentication','session fixation']),
                ('A08',['deserializ','integrity']),('A09',['logging','log injection']),
                ('A10',['exception','stack trace','error handling']),('A06',['insecure design'])]
    return next((c for c,keys in heuristics if any(k in s for k in keys)),None)

def clean(v,limit=1000):
    s=re.sub(r'(?i)(authorization\s*[:=]\s*|password\s*[:=]\s*|token\s*[:=]\s*)[^\s,;]+',r'\1[REDACTADO]',str(v or ''))
    return s[:limit]

def normalize_zap(raw):
    for site in raw.get('site',[]):
        for a in site.get('alerts',[]):
            instances=a.get('instances') or [{}]
            for inst in instances:
                yield dict(tool='ZAP',rule=str(a.get('pluginid','')),title=clean(a.get('name') or a.get('alert')),
                           description=clean(a.get('desc')),severity=str(a.get('riskdesc') or a.get('risk') or 'informational'),
                           confidence=str(a.get('confidence') or ''),url=clean(inst.get('uri') or site.get('@name')),
                           evidence=clean(inst.get('evidence') or a.get('evidence')),cwe=f'CWE-{a.get("cweid")}' if a.get('cweid') else '')

def normalize_semgrep(raw):
    for r in raw.get('results',[]):
        extra=r.get('extra',{});meta=extra.get('metadata',{})
        cwe=meta.get('cwe',''); cwe=', '.join(cwe) if isinstance(cwe,list) else str(cwe)
        yield dict(tool='Semgrep',rule=str(r.get('check_id','')),title=clean(extra.get('message') or r.get('check_id')),
                   description=clean(extra.get('message')),severity=str(extra.get('severity') or 'info'),
                   confidence='',url=clean(f'{r.get("path", "")}:{r.get("start",{}).get("line", "")}'),
                   evidence=clean(extra.get('lines') or ''),cwe=cwe)

def normalize(raw,source):
    if isinstance(raw,list):
        return [dict(tool='genérico',rule='',title=clean(r.get('title')),description=clean(r.get('description')),
                     severity=clean(r.get('severity') or ''),confidence='',url=clean(r.get('url')),
                     evidence=clean(r.get('evidence')),cwe=clean(r.get('cwe'))) for r in raw]
    if isinstance(raw,dict) and 'site' in raw:return list(normalize_zap(raw))
    if isinstance(raw,dict) and 'results' in raw:return list(normalize_semgrep(raw))
    raise ValueError(f'Formato no reconocido en {source}. Se espera JSON de ZAP, Semgrep o lista de hallazgos.')

def priority(s):
    s=s.lower()
    if 'critical' in s or 'crític' in s:return 4
    if 'high' in s or 'alto' in s or s.strip() == 'error':return 3
    if 'medium' in s or 'medio' in s or s.strip() == 'warning':return 2
    if 'low' in s or 'bajo' in s:return 1
    return 0

def review_lookup(path):
    if not path:return {}
    x=json.loads(Path(path).read_text(encoding='utf8'))
    return x if isinstance(x,dict) else {}

def optional_ollama(item,model):
    if not model:return None
    prompt=("Eres un asistente de TRIAGE de seguridad. No inventes hechos ni vulnerabilidades. "
           "Devuelve una explicación breve en español limitada a la evidencia suministrada; "
           "si no es concluyente pide revisión humana. No escribas comandos de explotación.\n"+json.dumps({
             k:item.get(k) for k in ['title','category','description','evidence','severity','cwe']},ensure_ascii=False))
    payload=json.dumps({'model':model,'prompt':prompt,'stream':False}).encode()
    req=urllib.request.Request('http://127.0.0.1:11434/api/generate',data=payload,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=20) as response:
        answer=json.load(response)
    return clean(answer.get('response',''),2500)

def build(paths,review,model):
    out=[];input_hashes=[]
    for path in paths:
        p=Path(path).resolve()
        if not p.is_file():raise FileNotFoundError(p)
        input_hashes.append({'name':p.name,'sha256':sha256_file(p)})
        records=normalize(json.loads(p.read_text(encoding='utf8')),p.name)
        for r in records:
            cat=cat_for(r.get('cwe'),r.get('rule'),r.get('title'),r.get('description'))
            canonical=json.dumps({k:r.get(k) for k in ['tool','rule','title','url','evidence']},sort_keys=True,ensure_ascii=False)
            fid=hashlib.sha256(canonical.encode()).hexdigest()[:14]
            if any(x['id']==fid for x in out):continue
            dec=review.get(fid,'pendiente')
            if dec not in ('confirmado','descartado','pendiente'):dec='pendiente'
            item={**r,'id':fid,'category':cat or 'SIN_CLASIFICAR',
                  'category_name':CATS.get(cat,'Requiere mapeo manual'),
                  'priority':priority(r['severity']), 'status':dec,
                  'recommendation':REMEDIATION.get(cat,'Requiere análisis experto y revisión de evidencia.'),
                  'ai_mode':'no solicitada','ai_explanation':None}
            if model:
                try:
                    item['ai_explanation']=optional_ollama(item,model)
                    item['ai_mode']='ollama-local'
                except Exception as e:
                    item['ai_mode']='ollama-local-no-disponible'
                    item['ai_explanation']='No se pudo consultar el modelo; se mantiene interpretación determinista.'
            out.append(item)
    return {'metadata':{'generated_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
                        'taxonomy':'OWASP Top 10:2025','inputs':input_hashes,
                        'model':model or 'no utilizado','execution_mode':'importación offline, sin escaneo activo',
                        'finding_count':len(out)},'findings':sorted(out,key=lambda x:(-x['priority'],x['category'],x['id']))}

def html_report(result):
    meta=result['metadata'];rows=[]
    for v in result['findings']:
        cols=[v['id'],v['category'],v['title'],v['severity'],v['status'],v['tool'],v['url'],v['recommendation']]
        rows.append('<tr>'+''.join('<td>'+html.escape(str(s))+'</td>' for s in cols)+'</tr>')
    tr='\n'.join(rows)
    return f'''<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Auditoría OWASP 2025</title>
<style>body{{font:14px Arial,sans-serif;margin:2rem;color:#17202b}}h1{{color:#8b183d}}
table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ccd2d9;padding:8px;text-align:left;vertical-align:top}}
th{{background:#f1e5eb}}tr:nth-child(even){{background:#f9f9fa}}.notice{{background:#f6f1f3;padding:12px}}</style></head><body>
<h1>Hallazgos normalizados | OWASP Top 10:2025</h1>
<p class="notice">INFORME ACADÉMICO. No certifica seguridad ni reemplaza revisión profesional. Importación offline; no se realizaron pruebas activas.</p>
<p>Fecha UTC: {html.escape(meta['generated_at_utc'])} | Hallazgos: {meta['finding_count']} | LLM: {html.escape(meta['model'])}</p>
<h2>Hallazgos</h2><table><thead><tr><th>ID</th><th>OWASP</th><th>Hallazgo</th><th>Riesgo reportado</th><th>Revisión</th><th>Fuente</th><th>Ubicación</th><th>Recomendación</th></tr></thead>
<tbody>{tr}</tbody></table><h2>Integridad de insumos</h2><pre>{html.escape(json.dumps(meta['inputs'],indent=2,ensure_ascii=False))}</pre></body></html>'''

def main(argv=None):
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('json',nargs='+',help='Archivos JSON de ZAP, Semgrep o lista genérica')
    a.add_argument('--review',help='Archivo opcional JSON {id: confirmado|descartado|pendiente}')
    a.add_argument('--model',help='Modelo local de Ollama, p.ej. llama3.2 (opcional)')
    a.add_argument('--out',default='salida',help='Directorio de salida')
    opt=a.parse_args(argv)
    result=build(opt.json,review_lookup(opt.review),opt.model)
    out=Path(opt.out);out.mkdir(parents=True,exist_ok=True)
    (out/'hallazgos.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf8')
    (out/'informe.html').write_text(html_report(result),encoding='utf8')
    print(f"Generados {out/'hallazgos.json'} y {out/'informe.html'}; hallazgos: {len(result['findings'])}")
    return 0

if __name__=='__main__':raise SystemExit(main())
