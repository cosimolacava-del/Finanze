from pathlib import Path

p=Path('index.html')
s=p.read_text(encoding='utf-8')
start=s.index('function abbinaMovimentiEstratto(')
end=s.index('\nfunction classificaScostamento', start)
nuovo=r'''function tipoSemanticoMovimento(o,origine){
  const testo=normalizzaTestoMatch((o&&o.descrizione)||'')+' '+normalizzaTestoMatch((o&&o.riga)||'');
  if((origine==='app'&&o&&o.tipo==='stipendio')||/\b(emolumenti|stipendio|stipendi|retribuzione|retribuzioni|competenze|salary|paga)\b/.test(testo))return 'stipendio';
  return null;
}

function abbinaMovimentiEstratto(bancaLista,appLista,bancaValore,appValore){
  const candidati=[];
  bancaLista.forEach((b,bi)=>appLista.forEach((a,ai)=>{
    const vb=Number(bancaValore(b)||0),va=Number(appValore(a)||0),delta=Math.abs(vb-va);
    const tipoB=tipoSemanticoMovimento(b,'banca'),tipoA=tipoSemanticoMovimento(a,'app');
    const stessoTipoForte=tipoB&&tipoA&&tipoB===tipoA;
    const tolleranza=stessoTipoForte&&tipoB==='stipendio' ? Math.max(5,Math.min(250,Math.max(vb,va)*0.06)) : 0.05;
    if(delta>tolleranza)return;
    const sim=similaritaDescrizione(b.descrizione||b.riga||'',a.descrizione||'');
    let giornoScore=0;
    if(b.giorno&&a.giorno){
      const dg=Math.abs(Number(b.giorno)-Number(a.giorno));
      giornoScore=dg===0?30:(dg<=2?22:(dg<=5?12:(dg<=10?4:-8)));
    }
    const semScore=stessoTipoForte?140:0;
    const rel=delta/Math.max(1,vb,va);
    const score=120-Math.min(80,rel*1000)+sim*45+giornoScore+semScore;
    candidati.push({bi,ai,score,delta,sim,tipo:stessoTipoForte?tipoB:null});
  }));
  candidati.sort((x,y)=>y.score-x.score || x.delta-y.delta || y.sim-x.sim);
  const usatiB=new Set(),usatiA=new Set(),abbinati=[];
  candidati.forEach(c=>{
    if(usatiB.has(c.bi)||usatiA.has(c.ai))return;
    usatiB.add(c.bi);usatiA.add(c.ai);
    abbinati.push({banca:bancaLista[c.bi],app:appLista[c.ai],score:c.score,tipo:c.tipo});
  });
  const soloBanca=bancaLista.filter((_,i)=>!usatiB.has(i));
  const soloApp=appLista.filter((_,i)=>!usatiA.has(i));
  return {abbinati,soloBanca,soloApp};
}
'''
s=s[:start]+nuovo+s[end:]
if 'Build index: 2026.08.28-09' not in s:
    raise SystemExit('build -09 non trovata')
s=s.replace('Build index: 2026.08.28-09','Build index: 2026.08.28-10',1)
p.write_text(s,encoding='utf-8')
