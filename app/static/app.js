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

 // Control de Convocatorias y Notificaciones en Actas y Reuniones
 const convSelect = document.getElementById('convocatoria-meeting-select');
 if (convSelect) {
  convSelect.addEventListener('change', function() {
   if (this.value) {
    window.location.href = '/actas?tab=convocatorias&meeting_id=' + encodeURIComponent(this.value);
   } else {
    window.location.href = '/actas?tab=convocatorias';
   }
  });
 }

 const btnMarcarNotif = document.getElementById('btn-marcar-todos-notif');
 const btnDesmarcarNotif = document.getElementById('btn-desmarcar-todos-notif');

 function updateConvocatoriaSummary() {
  const checks = document.querySelectorAll('.convocatoria-check');
  if (!checks.length) return;
  const total = checks.length;
  let notificados = 0;
  checks.forEach(function(c) {
   const badgeId = c.dataset.badge;
   const badge = badgeId ? document.getElementById(badgeId) : null;
   if (c.checked) {
    notificados++;
    if (badge) {
     badge.className = 'pill green';
     badge.textContent = 'Notificado';
    }
   } else {
    if (badge) {
     badge.className = 'pill orange';
     badge.textContent = 'No notificado';
    }
   }
  });
  const pendientes = total - notificados;

  const elTot = document.getElementById('resumen-notif-total');
  const elSi = document.getElementById('resumen-notif-si');
  const elNo = document.getElementById('resumen-notif-no');
  if (elTot) elTot.textContent = total;
  if (elSi) elSi.textContent = notificados;
  if (elNo) elNo.textContent = pendientes;

  const sideSi = document.getElementById('side-notif-si');
  const sideNo = document.getElementById('side-notif-no');
  if (sideSi) sideSi.textContent = notificados;
  if (sideNo) sideNo.textContent = pendientes;
 }

 if (btnMarcarNotif) {
  btnMarcarNotif.addEventListener('click', function() {
   document.querySelectorAll('.convocatoria-check').forEach(function(cb) {
    if (!cb.disabled) cb.checked = true;
   });
   updateConvocatoriaSummary();
  });
 }

 if (btnDesmarcarNotif) {
  btnDesmarcarNotif.addEventListener('click', function() {
   document.querySelectorAll('.convocatoria-check').forEach(function(cb) {
    if (!cb.disabled) cb.checked = false;
   });
   updateConvocatoriaSummary();
  });
 }

 document.querySelectorAll('.convocatoria-check').forEach(function(cb) {
  cb.addEventListener('change', updateConvocatoriaSummary);
 });

 // Auto-búsqueda inteligente por Cédula o Unidad
 const cedulaInput = document.getElementById('lookup-cedula');
 const unitInput = document.getElementById('lookup-unit');
 const liveCard = document.getElementById('lookup-live-card');
 const socioDisplay = document.getElementById('auto-socio-name-display');
 const socioSelect = document.getElementById('fld-socio_id');
 const unitSelect = document.getElementById('fld-unit_id');
 const toggleManual = document.getElementById('btn-toggle-manual-socio');

 if (cedulaInput || unitInput || socioDisplay) {
  let lookupSocios = [];
  let lookupUnits = [];
  const scriptSocios = document.getElementById('socio-lookup-data');
  const scriptUnits = document.getElementById('unit-lookup-data');
  if (scriptSocios) {
   try { lookupSocios = JSON.parse(scriptSocios.textContent || '[]'); } catch(e){}
  }
  if (scriptUnits) {
   try { lookupUnits = JSON.parse(scriptUnits.textContent || '[]'); } catch(e){}
  }

  function findMatchByCedula(ced) {
   if (!ced) return null;
   const clean = ced.trim().toLowerCase();
   return lookupSocios.find(s => s.cedula && s.cedula.toLowerCase() === clean) ||
          lookupSocios.find(s => s.cedula && s.cedula.toLowerCase().startsWith(clean)) ||
          lookupUnits.find(u => u.cedula && u.cedula.toLowerCase() === clean);
  }

  function findMatchByUnit(code) {
   if (!code) return null;
   const clean = code.trim().toLowerCase();
   let u = lookupUnits.find(item => item.unit_code && item.unit_code.toLowerCase() === clean);
   if (u) {
    const s = lookupSocios.find(item => String(item.socio_id) === String(u.socio_id));
    return s || {
     socio_id: u.socio_id,
     name: u.socio_name,
     cedula: u.cedula,
     unit_id: u.unit_id,
     unit_code: u.unit_code,
     plate: u.plate,
     active: 1
    };
   }
   const num = clean.replace(/\D/g, '');
   if (num) {
    u = lookupUnits.find(item => {
     if (!item.unit_code) return false;
     const itemNum = item.unit_code.replace(/\D/g, '');
     return itemNum && (parseInt(itemNum, 10) === parseInt(num, 10));
    });
    if (u) {
     const s = lookupSocios.find(item => String(item.socio_id) === String(u.socio_id));
     return s || {
      socio_id: u.socio_id,
      name: u.socio_name,
      cedula: u.cedula,
      unit_id: u.unit_id,
      unit_code: u.unit_code,
      plate: u.plate,
      active: 1
     };
    }
   }
   return null;
  }

  function applyMatch(data, source) {
   if (!data) return;

   if (socioDisplay && data.name) {
    socioDisplay.value = data.name;
   }

   const plateDisplay = document.getElementById('display-vehicle-plate');
   if (plateDisplay) {
    plateDisplay.value = data.plate ? (data.plate + (data.unit_code ? ' · Unidad ' + data.unit_code : '')) : 'Sin vehículo asignado';
   }

   if (socioSelect && data.socio_id) {
    socioSelect.value = String(data.socio_id);
   }

   if (unitSelect && data.unit_id) {
    unitSelect.value = String(data.unit_id);
   }

   if (source !== 'cedula' && cedulaInput && data.cedula) {
    cedulaInput.value = data.cedula;
   }
   if (source !== 'unit' && unitInput && data.unit_code) {
    unitInput.value = data.unit_code;
   }

   if (liveCard) {
    const elName = document.getElementById('card-socio-name');
    const elCed = document.getElementById('card-socio-cedula');
    const elUnit = document.getElementById('card-unit-code');
    const elPlate = document.getElementById('card-plate');
    const elStatus = document.getElementById('card-status');
    if (elName) elName.textContent = data.name || 'Sin socio asignado';
    if (elCed) elCed.textContent = data.cedula || 'Sin cédula registrada';
    if (elUnit) elUnit.textContent = data.unit_code ? 'Unidad ' + data.unit_code : 'Sin unidad asignada';
    if (elPlate) elPlate.textContent = data.plate ? 'Placa ' + data.plate : 'Sin placa asignada';
    if (elStatus) {
     elStatus.textContent = (data.active === 0) ? 'Inactivo' : 'Activo';
     elStatus.className = 'pill ' + ((data.active === 0) ? 'orange' : 'green');
    }
    liveCard.style.display = 'block';
   }
  }

  if (cedulaInput) {
   const handleCedulaInput = () => {
    const match = findMatchByCedula(cedulaInput.value);
    if (match) applyMatch(match, 'cedula');
   };
   cedulaInput.addEventListener('input', handleCedulaInput);
   cedulaInput.addEventListener('change', handleCedulaInput);
  }

  if (unitInput) {
   const handleUnitInput = () => {
    const match = findMatchByUnit(unitInput.value);
    if (match) applyMatch(match, 'unit');
   };
   unitInput.addEventListener('input', handleUnitInput);
   unitInput.addEventListener('change', handleUnitInput);
  }

  if (socioSelect) {
   socioSelect.addEventListener('change', () => {
    const val = socioSelect.value;
    const match = lookupSocios.find(s => String(s.socio_id) === String(val));
    if (match) applyMatch(match, 'select');
   });
  }

  if (toggleManual && socioSelect) {
   toggleManual.addEventListener('click', (e) => {
    e.preventDefault();
    if (socioSelect.style.display === 'none') {
     socioSelect.style.display = 'block';
     toggleManual.textContent = 'Ocultar selector desplegable manual';
    } else {
     socioSelect.style.display = 'none';
     toggleManual.textContent = '(Opcional) ¿Elegir nombre de la lista desplegable?';
    }
   });
  }

  if (socioSelect && socioSelect.value) {
   const initMatch = lookupSocios.find(s => String(s.socio_id) === String(socioSelect.value));
   if (initMatch) applyMatch(initMatch, 'init');
  }
 }
});
