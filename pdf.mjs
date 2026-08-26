// Wrapper della libreria PDF.js originale.
// Mantiene le API PDF.js ma ripulisce il testo BPER PRIMA che il parser dell'app
// lo analizzi, evitando che le date interne alle descrizioni vengano interpretate
// come nuovi movimenti.
export * from "./pdf-lib-original.mjs";
import * as PDFJS from "./pdf-lib-original.mjs";
export default PDFJS;

function sanitizePdfText(s=""){
  return String(s)
    .replace(/\b\d{1,2}\.\d{1,2}\.\d{4}\/\d{1,2}\.\d{2}\.\d{2}\b/g," ")
    .replace(/\b(?:del\s+)?\d{1,2}\.\d{1,2}\.\d{4}\b/gi," ")
    .replace(/\s+/g," ")
    .trim();
}

function wrapTextStream(stream){
  return new ReadableStream({
    async start(controller){
      const reader=stream.getReader();
      try{
        while(true){
          const {value,done}=await reader.read();
          if(done) break;
          if(value && Array.isArray(value.items)){
            value.items=value.items.map(it=>({...it,str:sanitizePdfText(it.str)}));
          }
          controller.enqueue(value);
        }
        controller.close();
      }catch(e){controller.error(e);}
      finally{try{reader.releaseLock&&reader.releaseLock();}catch(_){}}
    },
    cancel(reason){try{return stream.cancel(reason);}catch(_){}}
  });
}

function wrapPage(page){
  return new Proxy(page,{
    get(target,prop,receiver){
      if(prop==="streamTextContent") return (...args)=>wrapTextStream(target.streamTextContent(...args));
      const v=Reflect.get(target,prop,receiver);
      return typeof v==="function" ? v.bind(target) : v;
    }
  });
}

function wrapPdf(pdf){
  return new Proxy(pdf,{
    get(target,prop,receiver){
      if(prop==="getPage") return async n=>wrapPage(await target.getPage(n));
      const v=Reflect.get(target,prop,receiver);
      return typeof v==="function" ? v.bind(target) : v;
    }
  });
}

// Export esplicito che prevale su export *.
export function getDocument(...args){
  const task=PDFJS.getDocument(...args);
  const wrappedPromise=task.promise.then(wrapPdf);
  return new Proxy(task,{
    get(target,prop,receiver){
      if(prop==="promise") return wrappedPromise;
      const v=Reflect.get(target,prop,receiver);
      return typeof v==="function" ? v.bind(target) : v;
    }
  });
}

// Riconciliazione smart degli scostamenti.
const norm=(s="")=>String(s).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/\b(operazione|carta|contabilizzato|pagamento|addebito|sdd|rid|sepa|ita|it|eur)\b/g," ").replace(/[^a-z0-9]+/g," ").replace(/\s+/g," ").trim();
const safeVal=(o,valore)=>{const n=Number(valore(o));return Number.isFinite(n)?Math.abs(n):0;};
function motivoItem(o){const s=norm(o.descrizione||o.riga||"");const m=[];if(o.pending)m.push("movimento ancora da contabilizzare");if(/american express|amex/.test(s))m.push("addebito carta aggregato: possibile doppio conteggio");if(/paypal/.test(s))m.push("pagamento intermediato: verifica eventuale doppio conteggio");if(/commission/.test(s))m.push("commissione separata dall'addebito principale");return m;}
function trovaResponsabiliSmart(lista,target,valore){
  target=Math.abs(Number(target)||0);if(!target||!Array.isArray(lista)||!lista.length)return[];
  const exact=Math.max(.75,target*.001),good=Math.max(3,target*.01);
  const raw=lista.map((o,i)=>({o,i,v:safeVal(o,valore),k:norm(o.descrizione||o.riga||"")})).filter(x=>x.v>.001);
  const out=[],seen=new Set();
  const add=(arr,reason="")=>{const key=arr.map(x=>x.i).sort((a,b)=>a-b).join("-");if(!arr.length||seen.has(key))return;seen.add(key);const totale=arr.reduce((s,x)=>s+x.v,0),residuo=Math.abs(target-totale),rel=residuo/target;const conf=residuo<=exact?"molto probabile":(residuo<=good||rel<=.03?"probabile":"possibile");const why=[...new Set(arr.flatMap(x=>motivoItem(x.o)).concat(reason?[reason]:[]))];const suffix=` [${conf}; residuo ${residuo.toFixed(2).replace('.',',')} €${why.length?'; '+why.join('; '):''}]`;out.push({items:arr.map((x,j)=>({...x.o,descrizione:(x.o.descrizione||x.o.riga||"Operazione")+(j===0?suffix:"")})),totale,residuo,score:(conf==="molto probabile"?0:conf==="probabile"?1:2)*100000+residuo});};
  raw.forEach(x=>{if(Math.abs(target-x.v)<=Math.max(good,target*.08))add([x],"importo singolo vicino allo scostamento");});
  const pool=[...raw].sort((a,b)=>Math.abs(target-a.v)-Math.abs(target-b.v)).slice(0,80);
  for(let i=0;i<pool.length;i++)for(let j=i+1;j<pool.length;j++)if(Math.abs(target-pool[i].v-pool[j].v)<=Math.max(good,target*.05))add([pool[i],pool[j]],"somma di due movimenti vicina allo scostamento");
  for(let i=0;i<Math.min(pool.length,45);i++)for(let j=i+1;j<Math.min(pool.length,45);j++)for(let k=j+1;k<Math.min(pool.length,45);k++){const sum=pool[i].v+pool[j].v+pool[k].v;if(Math.abs(target-sum)<=Math.max(good,target*.03))add([pool[i],pool[j],pool[k]],"somma di tre movimenti vicina allo scostamento");if(out.length>30)break;}
  out.sort((a,b)=>a.score-b.score||a.items.length-b.items.length);return out.slice(0,8).map(({items,totale})=>({items,totale}));
}
globalThis.trovaResponsabiliScostamento=trovaResponsabiliSmart;
