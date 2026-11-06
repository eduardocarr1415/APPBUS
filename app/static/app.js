'use strict';
document.addEventListener('DOMContentLoaded',()=>{
 const menu=document.querySelector('[data-menu-toggle]');
 if(menu)menu.addEventListener('click',()=>document.querySelector('#sidebar')?.classList.toggle('open'));
 document.addEventListener('click',e=>{
  const btn=e.target.closest('[data-copy-target]');
  if(!btn)return;
  const target=document.getElementById(btn.dataset.copyTarget);
  if(target&&navigator.clipboard?.writeText){navigator.clipboard.writeText(target.textContent).then(()=>{btn.textContent='Copiado';});}
 });
 document.querySelectorAll('form').forEach(form=>form.addEventListener('submit',e=>{
  const btn=e.submitter;
  if(btn?.dataset.confirm&&!window.confirm(btn.dataset.confirm))e.preventDefault();
 }));

 // Control de Asistencia en Actas y Reuniones
 const meetingSelect = document.getElementById('asistencia-meeting-select');
 if (meetingSelect) {
  meetingSelect.addEventListener('change', function() {
   if (this.value) {
    window.location.href = '/actas?tab=asistencia&meeting_id=' + encodeURIComponent(this.value);
   } else {
    window.location.href = '/actas?tab=asistencia';
   }
  });
 }

 const btnMarcar = document.getElementById('btn-marcar-todos');
 const btnDesmarcar = document.getElementById('btn-desmarcar-todos');

 function updateAsistenciaSummary() {
  const checks = document.querySelectorAll('.asistencia-check');
  if (!checks.length) return;
  const total = checks.length;
  let asistieron = 0;
  checks.forEach(function(c) {
   if (c.checked) asistieron++;
  });
  const ausentes = total - asistieron;

  const elTot = document.getElementById('resumen-convocados');
  const elAsis = document.getElementById('resumen-asistentes');
  const elAus = document.getElementById('resumen-ausentes');
  if (elTot) elTot.textContent = total;
  if (elAsis) elAsis.textContent = asistieron;
  if (elAus) elAus.textContent = ausentes;

  const sideConvocados = document.getElementById('side-convocados');
  const sideAsistentes = document.getElementById('side-asistentes');
  const sideAusentes = document.getElementById('side-ausentes');
  if (sideConvocados) sideConvocados.innerHTML = '<strong>' + total + '</strong>';
  if (sideAsistentes) sideAsistentes.textContent = asistieron;
  if (sideAusentes) sideAusentes.textContent = ausentes;
 }

 if (btnMarcar) {
  btnMarcar.addEventListener('click', function() {
   document.querySelectorAll('.asistencia-check').forEach(function(cb) {
    if (!cb.disabled) cb.checked = true;
   });
   updateAsistenciaSummary();
  });
 }

 if (btnDesmarcar) {
  btnDesmarcar.addEventListener('click', function() {
   document.querySelectorAll('.asistencia-check').forEach(function(cb) {
    if (!cb.disabled) cb.checked = false;
   });
   updateAsistenciaSummary();
  });
 }

 document.querySelectorAll('.asistencia-check').forEach(function(cb) {
  cb.addEventListener('change', updateAsistenciaSummary);
 });
});
