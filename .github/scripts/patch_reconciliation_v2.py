from pathlib import Path

p = Path('index.html')
s = p.read_text(encoding='utf-8')

start = s.index('function trovaResponsabiliScostamento(')
end = s.index('\nfunction renderAnalisiEstratto()', start)

nuovo = '''function abbinaMovimentiEstratto(bancaLista,appLista,bancaValore,appValore){
  const candidati=[];
  bancaLista.forEach((b,bi)=>appLista.forEach((a,ai)=>{
    const vb=Number(bancaValore(b)||0),va=Number(appValore(a)||0),delta=Math.abs(vb-va);
    if(delta>0.05)return;
    const sim=similaritaDescrizione(b.descrizione||b.riga||'',a.descrizione||'');
    let giornoScore=0;
    if(b.giorno&&a.giorno){
      const dg=Math.abs(Number(b.giorno)-Number(a.giorno));
      giornoScore=dg===0?30:(dg<=2?22:(dg<=5?12:(dg<=10?4:-8)));
    }
    const score=120-Math.min(50,delta*1000)+sim*45+giornoScore;
    candidati.push({bi,ai,score,delta,sim});
  }));
  candidati.sort((x,y)=>y.score-x.score || x.delta-y.delta || y.sim-x.sim);
  const usatiB=new Set(),usatiA=new Set(),abbinati=[];
  candidati.forEach(c=>{
    if(usatiB.has(c.bi)||usatiA.has(c.ai))return;
    usatiB.add(c.bi);usatiA.add(c.ai);
    abbinati.push({banca:bancaLista[c.bi],app:appLista[c.ai],score:c.score});
  });
  const soloBanca=bancaLista.filter((_,i)=>!usatiB.has(i));
  const soloApp=appLista.filter((_,i)=>!usatiA.has(i));
  return {abbinati,soloBanca,soloApp};
}

function classificaScostamento(diff,match,bancaValore,appValore){
  if(Math.abs(diff)<=1)return [];
  const out=[];
  match.soloBanca.forEach(o=>out.push({origine:'banca',tipo:'solo_banca',items:[o],totale:Number(bancaValore(o)||0)}));
  match.soloApp.forEach(o=>out.push({origine:'app',tipo:'solo_app',items:[o],totale:Number(appValore(o)||0)}));
  out.forEach(r=>{
    const coerente=(diff>0&&r.origine==='banca')||(diff<0&&r.origine==='app');
    r.priorita=(coerente?1000:0)+Math.min(999,Math.abs(r.totale));
  });
  out.sort((a,b)=>b.priorita-a.priorita);
  return out.slice(0,20);
}

function confrontaEstratto(ops,anno,mese){
  const banca=ops.filter(o=>o.anno===anno&&o.mese===mese),app=operazioniCassaAttese(anno,mese);
  const isAmexBanca=o=>/american|amex/i.test(String(o.descrizione||"")+" "+String(o.riga||""));
  const bancaEntrate=banca.filter(o=>o.importo>0),bancaUscite=banca.filter(o=>o.importo<0&&!isAmexBanca(o));
  const appEntrate=app.filter(o=>o.segno>0),appUscite=app.filter(o=>o.segno<0&&o.tipo!=="amex");
  const totBancaEntrate=bancaEntrate.reduce((s,o)=>s+o.importo,0),totBancaUscite=bancaUscite.reduce((s,o)=>s+Math.abs(o.importo),0);
  const totAppEntrate=appEntrate.reduce((s,o)=>s+o.importo,0),totAppUscite=appUscite.reduce((s,o)=>s+o.importo,0);
  const diffEntrate=totBancaEntrate-totAppEntrate,diffUscite=totBancaUscite-totAppUscite;
  const matchEntrate=abbinaMovimentiEstratto(bancaEntrate,appEntrate,o=>o.importo,o=>o.importo);
  const matchUscite=abbinaMovimentiEstratto(bancaUscite,appUscite,o=>Math.abs(o.importo),o=>o.importo);
  return {anno,mese,banca,app,pending:banca.filter(o=>o.pending),totBancaEntrate,totBancaUscite,totAppEntrate,totAppUscite,diffEntrate,diffUscite,
    matchEntrate,matchUscite,
    responsabiliEntrate:classificaScostamento(diffEntrate,matchEntrate,o=>o.importo,o=>o.importo),
    responsabiliUscite:classificaScostamento(diffUscite,matchUscite,o=>Math.abs(o.importo),o=>o.importo)};
}
'''

s = s[:start] + nuovo + s[end:]

old = '''  const candidati=(titolo,arr,diff)=>{
    if(Math.abs(diff)<=1)return '';
    if(!arr.length)return `<div class="warn-box"><b>${titolo}</b><br>Nessun importo singolo o combinazione fino a 3 movimenti spiega esattamente lo scostamento di ${eur(Math.abs(diff))}.</div>`;
    return `<div><b style="font-size:12px">${titolo}</b><div class="statement-list">${arr.map(r=>`<div class="statement-row"><span>${r.items.map(o=>escapeHtml(o.descrizione||o.riga||"Operazione")).join(' + ')} <small style="color:${MUTED}">(${r.origine==='banca'?'nel PDF':'nell’app'})</small></span><b style="color:${RUST}">${eur(r.totale)}</b></div>`).join('')}</div></div>`;
  };'''
new = '''  const candidati=(titolo,arr,diff)=>{
    if(Math.abs(diff)<=1)return '';
    if(!arr.length)return `<div class="warn-box"><b>${titolo}</b><br>Tutti i movimenti con importo confrontabile risultano già abbinati; lo scostamento richiede un controllo manuale.</div>`;
    return `<div><b style="font-size:12px">${titolo}</b><div class="statement-list">${arr.map(r=>{const o=r.items[0],d=o.giorno?String(o.giorno).padStart(2,'0')+' · ':'';return `<div class="statement-row"><span>${d}${escapeHtml(o.descrizione||o.riga||"Operazione")} <small style="color:${MUTED}">${r.origine==='banca'?'solo nel PDF':'solo nell’app'}</small></span><b style="color:${RUST}">${eur(r.totale)}</b></div>`;}).join('')}</div></div>`;
  };'''
if old not in s:
    raise SystemExit('renderer candidati non trovato')
s = s.replace(old, new, 1)

oldmsg = '<div class="warn-box">C’è uno scostamento: sotto trovi solo i movimenti singoli o le piccole combinazioni che potrebbero spiegarlo, calcolati sulla differenza.</div>'
newmsg = '<div class="warn-box">C’è uno scostamento: prima abbino automaticamente PDF e app per importo, giorno e descrizione; sotto mostro i movimenti rimasti senza controparte, ordinati per probabilità.</div>'
if oldmsg not in s:
    raise SystemExit('messaggio scostamento non trovato')
s = s.replace(oldmsg, newmsg, 1)
s = s.replace('Possibili responsabili dello scostamento entrate', 'Movimenti non abbinati — entrate', 1)
s = s.replace('Possibili responsabili dello scostamento uscite', 'Movimenti non abbinati — uscite', 1)

if 'Build index: 2026.08.27-08' not in s:
    raise SystemExit('build -08 non trovata')
s = s.replace('Build index: 2026.08.27-08', 'Build index: 2026.08.28-09', 1)
p.write_text(s, encoding='utf-8')
