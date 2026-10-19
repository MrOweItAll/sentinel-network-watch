"""Execute the real inline UI with a synthetic DOM/fetch; no browser or network."""
import shutil
import subprocess
import unittest

from sentinel_watch.console_ui import HTML


BOOTSTRAP = r"""
const assert=require('node:assert/strict');
class Element {
 constructor(tag='div'){this.tag=tag;this.children=[];this.textContent='';this.value='';this.className='';this.hidden=false;this.disabled=false;this.open=false;this.dataset={};this.events={};this.options=[];}
 append(...items){this.children.push(...items)}
 replaceChildren(...items){this.children=[...items]}
 addEventListener(name,handler){this.events[name]=handler}
 showModal(){this.open=true} close(){this.open=false}
 click(){return this.onclick?.()}
}
const elements=new Map(),decisionButtons=['recognize','investigate','unrecognized'].map(decision=>{const e=new Element('button');e.dataset.decision=decision;return e});
const document={hidden:false,getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id)},createElement(tag){return new Element(tag)},querySelectorAll(){return decisionButtons}};
document.getElementById('source').value='all';document.getElementById('direction').value='all';document.getElementById('review').value='pending';
document.getElementById('direction').options=['all','vendor_outgoing','vendor_incoming','unknown','listening'].map(value=>({value,disabled:false}));
const location={assign(){throw Error('Unexpected synthetic navigation')}};
let downloaded=[];URL.createObjectURL=blob=>{downloaded.push(blob);return 'blob:synthetic'};URL.revokeObjectURL=()=>{};
const setTimeout=()=>0,setInterval=()=>0;
const content=e=>e.textContent+' '+e.children.map(content).join(' ');
const copy=value=>JSON.parse(JSON.stringify(value));
const fixtureRow=i=>({id:'saved-'+i,source:'router',state:'history',direction:'vendor_outgoing',source_address:'192.0.2.10',source_port:null,destination_address:'198.51.100.20',destination_port:443,observed_at:1700000000,summary:i===624?'Late-only fixture':'Fixture '+i,application:'Unknown',severity:'INFO',reason:'Fixture evidence only'});
let retained=Array.from({length:625},(_,i)=>fixtureRow(i)),serverAnnotations={},requests=[];
const summary={available:true,state:'ok',generated_at:1700000000,collector_checked_at:1700000000,raw_retained_count:700,total_observations:625,row_errors:0,reason:'Fixture retained history'};
const fixtureSnapshot=()=>({generated_at:1700000000,connections:retained.slice(0,20),counters:[{interface:'fixture0',rx_bytes:1000,tx_bytes:2000}],devices:[{name:'Fixture device',addresses:['192.0.2.10']}],sources:{router:{state:'ok',checked_at:1700000000}},truncation:{connections_omitted:605}});
const response=(value,status=200)=>({status,ok:status<400,json:async()=>value});
function historyResponse(query){
 let rows=retained.filter(row=>(query.direction==='all'||row.direction===query.direction)&&JSON.stringify(row).toLowerCase().includes(query.search.toLowerCase())&&(query.review==='all'||(serverAnnotations[row.id]?.decision||'pending')===query.review));
 const page=rows.slice(query.offset,query.offset+query.limit),a={};for(const row of page)if(serverAnnotations[row.id])a[row.id]=copy(serverAnnotations[row.id]);
 return response({history:{...summary,rows:copy(page),total_matches:rows.length,offset:query.offset,limit:query.limit,has_more:query.offset+query.limit<rows.length},annotations:a});
}
let historyResponder=query=>Promise.resolve(historyResponse(query)),snapshotResponder=()=>Promise.resolve(response({snapshot:fixtureSnapshot(),annotations:copy(serverAnnotations),history:summary}));
async function fetch(path,options){
 assert.ok(['/api/snapshot','/api/history','/api/review'].includes(path));assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');
 const query=options.body?JSON.parse(options.body):null;requests.push({path,query,options});
 if(path==='/api/snapshot')return snapshotResponder();
 assert.equal(options.method,'POST');assert.equal(options.headers['X-CSRF-Token'],'synthetic-csrf');
 if(path==='/api/history'){assert.deepEqual(Object.keys(query).sort(),['direction','limit','offset','review','search']);return historyResponder(query)}
 serverAnnotations[query.id]={decision:query.decision,note:query.note};return response({ok:true,annotation:{ok:true,decision:query.decision,updated_at:1700000001,traffic_changed:false}});
}
"""


@unittest.skipUnless(shutil.which('node'), 'Optional JavaScript runtime is unavailable')
class ConsoleUIBehaviorTests(unittest.TestCase):
    def run_browser(self, scenario):
        script = HTML.split('<script nonce="__NONCE__">', 1)[1].split('</script>', 1)[0]
        script = script.split('(async()=>{try{csrf=', 1)[0]
        harness = BOOTSTRAP + script + '\n(async()=>{csrf="synthetic-csrf";\n' + scenario + r"""
})().catch(error=>{console.error(error.stack);process.exitCode=1});
"""
        result = subprocess.run([shutil.which('node'), '-'], input=harness, text=True,
                                encoding='utf-8', capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, 'Synthetic UI assertions failed: '+result.stderr[:4000])

    def test_pending_and_explicit_assessments_are_separate_from_evidence(self):
        self.assertIn('<option value="pending">Not reviewed</option>', HTML)
        self.run_browser(r"""
await refresh();assert.equal($('rows').children.length,20);
assert.equal($('rows').children[0].children[0].children[0].textContent,'Not reviewed');
assert.equal($('rows').children[0].children[0].children[0].className,'REVIEW');
assert.ok(content($('rows')).includes('Evidence: INFO · not an approval'));
retained[0].severity='WARNING';retained[0].reason='Fixture warning remains visible';
serverAnnotations={'saved-0':{decision:'recognize',note:'Known fixture'},'saved-1':{decision:'unrecognized',note:''},'saved-2':{decision:'investigate',note:''}};
await refresh();assert.equal($('rows').children.length,17);
$('review').value='all';await filtersChanged();
assert.ok(content($('rows')).includes('Recognized by you'));assert.ok(content($('rows')).includes('Kept unrecognized'));assert.ok(content($('rows')).includes('Investigate'));
assert.ok(content($('rows')).includes('Evidence: WARNING'));assert.ok(content($('rows')).includes('Fixture warning remains visible'));
$('review').value='unrecognized';await filtersChanged();assert.equal($('rows').children.length,1);assert.ok(content($('rows')).includes('Kept unrecognized'));
""")

    def test_history_search_and_paging_reach_beyond_the_recent_500(self):
        self.run_browser(r"""
await refresh();$('source').value='history';$('review').value='all';await filtersChanged();
assert.equal($('rows').children.length,50);assert.ok(content($('count')).includes('625 matching saved observations'));
await $('history-next').onclick();assert.equal(historyPage.offset,50);assert.equal(visibleRows()[0].id,'saved-50');
await changePage(600);assert.equal(visibleRows().length,25);assert.equal(visibleRows()[0].id,'saved-600');assert.equal($('history-next').disabled,true);
$('search').value='Late-only';await filtersChanged();assert.equal(historyPage.offset,0);assert.equal(visibleRows().length,1);assert.equal(visibleRows()[0].id,'saved-624');
assert.ok(content($('rows')).includes('Collector last seen'));assert.ok(content($('history-status')).includes('not live sessions'));
assert.ok(!latest.connections.some(row=>row.id==='saved-624'));
$('direction').value='unknown';await filtersChanged();assert.equal($('direction').value,'all');
""")

    def test_old_async_filter_and_refresh_responses_cannot_replace_new_results(self):
        self.run_browser(r"""
await refresh();$('source').value='history';$('review').value='all';
const waiting=[];historyResponder=query=>new Promise(resolve=>waiting.push({query,resolve}));
$('search').value='old';const oldRequest=filtersChanged();$('search').value='Late-only';const newRequest=filtersChanged();
waiting[1].resolve(historyResponse(waiting[1].query));await newRequest;assert.equal(visibleRows()[0].id,'saved-624');
waiting[0].resolve(historyResponse(waiting[0].query));await oldRequest;assert.equal(visibleRows()[0].id,'saved-624');
historyResponder=query=>Promise.resolve(historyResponse(query));
$('source').value='all';$('search').value='';await filtersChanged();openDetail(latest.connections[0]);$('note').value='Unsaved local note';
serverAnnotations['saved-0']={decision:'investigate',note:'Different saved server note'};await refresh();assert.equal($('note').value,'Unsaved local note');assert.equal($('detail').open,true);
""")

    def test_historical_review_saves_same_id_and_refreshes_pending_queue(self):
        self.run_browser(r"""
await refresh();$('source').value='history';$('search').value='Late-only';await filtersChanged();
openDetail(visibleRows()[0]);$('note').value='Reviewed synthetic endpoint';
await decisionButtons[0].onclick();
const save=requests.find(request=>request.path==='/api/review');assert.equal(save.query.id,'saved-624');assert.equal(save.query.note,'Reviewed synthetic endpoint');
assert.equal(visibleRows().length,0);assert.equal($('detail').open,false);
$('review').value='recognize';await filtersChanged();assert.equal(visibleRows()[0].id,'saved-624');assert.ok(content($('rows')).includes('Recognized by you'));
await refresh();assert.equal(annotation(visibleRows()[0]).note,'Reviewed synthetic endpoint');
""")

    def test_history_download_is_exactly_the_displayed_page_and_stays_bounded(self):
        self.run_browser(r"""
serverAnnotations={'saved-600':{decision:'investigate',note:'Fixture note'},'saved-0':{decision:'recognize',note:'Outside exported page'}};
await refresh();$('source').value='history';$('review').value='all';await filtersChanged();await changePage(600);
exportReport();assert.equal(downloaded.length,1);const report=JSON.parse(await downloaded[0].text());
assert.deepEqual(Object.keys(report).sort(),['annotations','snapshot']);assert.equal(report.snapshot.connections.length,25);assert.equal(report.snapshot.connections[0].id,'saved-600');
assert.equal(report.snapshot.report_scope.view,'saved_router_history_page');assert.equal(report.snapshot.report_scope.offset,600);assert.equal(report.snapshot.report_scope.complete_history_export,false);
assert.deepEqual(Object.keys(report.annotations),['saved-600']);assert.equal(report.snapshot.counters,undefined);assert.equal(report.snapshot.devices,undefined);
historyPage.rows[0].reason='x'.repeat(MAX_REPORT_BYTES);exportReport();assert.equal(downloaded.length,1);assert.ok($('error').textContent.includes('4 MiB'));
""")

    def test_saved_note_survives_real_response_shape_and_failed_refresh(self):
        self.run_browser(r"""
await refresh();const record=latest.connections[0];openDetail(record);$('note').value='Saved synthetic note';
snapshotResponder=()=>Promise.resolve(response({error:'E_SYNTHETIC_REFRESH'},503));
await decisionButtons[1].onclick();assert.ok($('error').textContent.includes('E_SYNTHETIC_REFRESH'));
assert.equal(annotation(record).decision,'investigate');assert.equal(annotation(record).note,'Saved synthetic note');
openDetail(record);assert.equal($('note').value,'Saved synthetic note');assert.equal($('detail').open,true);
""")

    def test_unavailable_history_and_pause_keep_current_host_view_usable(self):
        self.run_browser(r"""
await refresh();$('pause').onclick();assert.equal(paused,true);
historyResponder=()=>Promise.resolve(response({error:'E_HISTORY_UNAVAILABLE'},503));await $('browse-history').onclick();
assert.equal($('export').disabled,true);assert.ok(content($('history-status')).includes('Current iMac view remains available'));
$('source').value='all';await filtersChanged();assert.equal($('rows').children.length,20);assert.equal($('export').disabled,false);
assert.equal($('counters').children.length,1);assert.equal($('devices').children.length,1);
await $('refresh').onclick();assert.equal(paused,true);assert.equal($('rows').children.length,20);
""")


if __name__ == '__main__':
    unittest.main()
