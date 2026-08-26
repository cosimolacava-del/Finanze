// Wrapper della libreria PDF.js originale.
// Mantiene tutte le API PDF.js e aggiunge correzioni locali al parser/riconciliazione.
export * from "./pdf-lib-original.mjs";
import * as PDFJS from "./pdf-lib-original.mjs";
export default PDFJS;

const norm = (s="") => String(s)
  .toLowerCase()
  .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
  .replace(/\b(operazione|carta|contabilizzato|pagamento|addebito|sdd|rid|sepa|ita|it|eur)\b/g, " ")
  .replace(/[^a-z0-9]+/g, " ").replace(/\s+/g, " ").trim();

const safeVal = (o, valore) => {
  const n = Number(valore(o));
  return Number.isFinite(n) ? Math.abs(n) : 0;
};

const dataKey = (o) => {
  const y=Number(o.anno||0), m=Number(o.mese||0), d=Number(o.giorno||0);
  return y&&m&&d ? y*10000+m*100+d : 0;
};

function motivoItem(o){
  const s=norm(o.descrizione||o.riga||"");
  const motivi=[];
  if(o.pending) motivi.push("movimento ancora da contabilizzare");
  if(/american express|amex/.test(s)) motivi.push("addebito carta aggregato: verifica eventuale doppio conteggio delle singole spese");
  if(/paypal/.test(s)) motivi.push("pagamento intermediato: verifica che non sia già registrato con il negozio finale");
  if(/commission/.test(s)) motivi.push("commissione separata dall'addebito principale");
  return motivi;
}

function trovaResponsabiliSmart(lista,target,valore){
  target=Math.abs(Number(target)||0);
  if(!target || !Array.isArray(lista) || !lista.length) return [];

  const tollExact=Math.max(0.75, target*0.001);
  const tollGood=Math.max(3, target*0.01);
  const raw=lista.map((o,i)=>({o,i,v:safeVal(o,valore),k:norm(o.descrizione||o.riga||""),date:dataKey(o)})).filter(x=>x.v>0.001);
  const candidates=[];
  const seen=new Set();

  const add=(arr, reason="")=>{
    if(!arr.length) return;
    const ids=arr.map(x=>x.i).sort((a,b)=>a-b);
    const key=ids.join("-"); if(seen.has(key)) return; seen.add(key);
    const totale=arr.reduce((s,x)=>s+x.v,0);
    const residuo=Math.abs(target-totale);
    const rel=target?residuo/target:1;
    let conf="possibile";
    if(residuo<=tollExact) conf="molto probabile";
    else if(residuo<=tollGood || rel<=0.03) conf="probabile";
    const why=[];
    arr.forEach(x=>why.push(...motivoItem(x.o)));
    if(reason) why.push(reason);
    const suffix=` [${conf}; residuo ${residuo.toFixed(2).replace('.',',')} €${why.length?'; '+[...new Set(why)].join('; '):''}]`;
    const items=arr.map((x,j)=>({...x.o, descrizione:(x.o.descrizione||x.o.riga||"Operazione")+(j===0?suffix:"")}));
    candidates.push({items,totale,residuo,conf,score:(conf==="molto probabile"?0:conf==="probabile"?1:2)*100000+residuo});
  };

  raw.forEach(x=>{ if(Math.abs(target-x.v)<=Math.max(tollGood,target*0.08)) add([x],"importo singolo vicino allo scostamento"); });

  for(let i=0;i<raw.length;i++) for(let j=i+1;j<raw.length;j++){
    const a=raw[i],b=raw[j];
    const sameAmount=Math.abs(a.v-b.v)<=0.02;
    const sameDesc=a.k&&b.k&&(a.k===b.k || a.k.includes(b.k) || b.k.includes(a.k));
    if(sameAmount&&sameDesc) {
      if(Math.abs(target-a.v)<=Math.max(tollGood,target*0.08)) add([a],"possibile movimento duplicato");
      if(Math.abs(target-(a.v+b.v))<=Math.max(tollGood,target*0.08)) add([a,b],"due righe molto simili: possibile duplicazione");
    }
  }

  const pool=[...raw].sort((a,b)=>Math.abs(target-a.v)-Math.abs(target-b.v)).slice(0,80);
  for(let i=0;i<pool.length;i++) for(let j=i+1;j<pool.length;j++){
    const sum=pool[i].v+pool[j].v;
    if(Math.abs(target-sum)<=Math.max(tollGood,target*0.05)) add([pool[i],pool[j]],"somma di due movimenti vicina allo scostamento");
  }

  const cents=new Map();
  pool.forEach(x=>{const c=Math.round(x.v*100); if(!cents.has(c)) cents.set(c,[]); cents.get(c).push(x);});
  const targetC=Math.round(target*100), deltaC=Math.round(Math.max(tollGood,target*0.03)*100);
  for(let i=0;i<pool.length;i++) for(let j=i+1;j<pool.length;j++){
    const need=targetC-Math.round((pool[i].v+pool[j].v)*100);
    const step=Math.max(1,Math.floor(deltaC/12)||1);
    for(let dc=-deltaC;dc<=deltaC;dc+=step){
      const arr=cents.get(need+dc); if(!arr) continue;
      for(const z of arr){ if(z.i===pool[i].i||z.i===pool[j].i) continue; add([pool[i],pool[j],z],"somma di tre movimenti vicina allo scostamento"); }
    }
  }

  const groups=new Map();
  raw.forEach(x=>{if(!x.k)return; const g=x.k.split(" ").slice(0,3).join(" "); if(!g)return; if(!groups.has(g))groups.set(g,[]); groups.get(g).push(x);});
  groups.forEach(arr=>{
    if(arr.length<2||arr.length>8)return;
    const sum=arr.reduce((s,x)=>s+x.v,0);
    if(Math.abs(target-sum)<=Math.max(tollGood,target*0.08)) add(arr,"gruppo di movimenti con descrizione simile");
  });

  candidates.sort((a,b)=>a.score-b.score || a.items.length-b.items.length);
  return candidates.slice(0,8).map(({items,totale})=>({items,totale}));
}

// PDF BPER: PDF.js può spezzare le descrizioni su righe autonome. Quelle righe
// contengono spesso la data dell'operazione carta (es. 25.08.2026/03.43.13):
// il vecchio parser la scambiava per una nuova operazione e interpretava anche
// parti dell'orario come importi. Risultato: 129 movimenti invece dei 45 reali
// e uscite fortemente gonfiate.
// Le vere righe BPER iniziano invece nella colonna "Data operazione" con
// gg/mm/aaaa. Se nello stesso PDF vediamo sia righe vere sia righe spurie,
// teniamo esclusivamente le righe che iniziano con quella data.
function pulisciOperazioniBper(ops){
  if(!Array.isArray(ops) || !ops.length) return ops||[];
  const vere=ops.filter(o=>/^\s*\d{1,2}\/\d{1,2}\/\d{4}\b/.test(String(o.riga||"")));
  const sospette=ops.filter(o=>/^\s*\d{1,2}[.\-]\d{1,2}[.\-]\d{4}(?:\/|\s)/.test(String(o.riga||"")));
  // Attiva la correzione solo quando il pattern è chiaramente quello BPER,
  // così non tocchiamo estratti di altre banche che usano date con punti.
  if(vere.length>=5 && (sospette.length>=2 || ops.length>vere.length*1.15)) return vere;
  return ops;
}

// Salviamo i riferimenti originali prima di sostituirli. Le funzioni dichiarate
// nello script principale sono globali nella pagina e quindi aggiornabili qui.
const originalConfrontaEstratto = globalThis.confrontaEstratto;
if(typeof originalConfrontaEstratto === "function"){
  globalThis.confrontaEstratto = function(ops,anno,mese){
    return originalConfrontaEstratto(pulisciOperazioniBper(ops),anno,mese);
  };
}

globalThis.trovaResponsabiliScostamento = trovaResponsabiliSmart;
