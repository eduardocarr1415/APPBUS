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
 document.querySelectorAll('form').forEach(form=>{
  form.addEventListener('invalid',()=>form.classList.add('validation-attempted'),true);
  form.addEventListener('submit',e=>{
   const btn=e.submitter;
   if(btn?.dataset.confirm&&!window.confirm(btn.dataset.confirm))e.preventDefault();
  });
 });

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

 // ==========================================================================
 // NAVEGACIÓN INMEDIATA (Sin pantallas de carga ni esperas artificiales)
 // ==========================================================================
 const busOverlay = document.getElementById('bus-transition-overlay');

 // ==========================================================================
 // CONFIGURACIÓN Y VISTA PREVIA INTERACTIVA EN VIVO (LIVE PREVIEW EXTENDIDO)
 // ==========================================================================
 const configForm = document.getElementById('config-form');
 if (configForm) {
  // Pestañas de secciones de configuración
  document.querySelectorAll('.config-nav-btn').forEach(btn => {
   btn.addEventListener('click', () => {
    document.querySelectorAll('.config-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.config-section-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const targetId = btn.dataset.target;
    const targetPanel = document.getElementById(targetId);
    if (targetPanel) targetPanel.classList.add('active');
   });
  });

  const inCompanyName = document.getElementById('cfg-company-name');
  const inCompanySlogan = document.getElementById('cfg-company-slogan');
  const inFooterText = document.getElementById('cfg-footer-text');
  const inPrimaryColor = document.getElementById('cfg-primary-color');
  const inPrimaryHex = document.getElementById('cfg-primary-hex');
  const inSidebarColor = document.getElementById('cfg-sidebar-color');
  const inSidebarHex = document.getElementById('cfg-sidebar-hex');
  const inAccentColor = document.getElementById('cfg-accent-color');
  const inAccentHex = document.getElementById('cfg-accent-hex');
  const inPageBgColor = document.getElementById('cfg-page-bg-color');
  const inPageBgHex = document.getElementById('cfg-page-bg-hex');
  const inCardBgColor = document.getElementById('cfg-card-bg-color');
  const inCardBgHex = document.getElementById('cfg-card-bg-hex');
  const inSidebarTextColor = document.getElementById('cfg-sidebar-text-color');
  const inSidebarTextHex = document.getElementById('cfg-sidebar-text-hex');
  const inBorderRadius = document.getElementById('cfg-border-radius');
  const inFontFamily = document.getElementById('cfg-font-family');
  const inTabsStyle = document.getElementById('cfg-tabs-style');
  const inBusLedText = document.getElementById('cfg-bus-led-text');

  const mockBrandTitle = document.getElementById('mockup-brand-title');
  const mockBrandSlogan = document.getElementById('mockup-brand-slogan');
  const mockFooterText = document.getElementById('mockup-footer-text');
  const mockSidebar = document.getElementById('mockup-sidebar');
  const mockBtnPrimary = document.getElementById('mockup-btn-primary');
  const mockAvatar = document.getElementById('mockup-avatar');
  const mockNavActive = document.getElementById('mockup-nav-active');
  const mockCardAccent = document.getElementById('mockup-card-accent');
  const mockFrame = document.getElementById('live-mockup-frame');
  const mockMain = document.querySelector('.mockup-main');
  const mockLogoImg = document.getElementById('mockup-logo-img');
  const mockBannerImg = document.getElementById('mockup-banner-img');
  const mockTabsContainer = document.getElementById('mockup-tabs-container');
  const mockUnitBadge = document.getElementById('mockup-unit-badge');
  const btnDemoAnim = document.getElementById('btn-demo-bus-anim');

  function updateMockup() {
   if (mockBrandTitle && inCompanyName) mockBrandTitle.textContent = inCompanyName.value || 'Buses Guaytacama';
   if (mockBrandSlogan && inCompanySlogan) mockBrandSlogan.textContent = inCompanySlogan.value || '';
   if (mockFooterText && inFooterText) mockFooterText.textContent = inFooterText.value || '';

   const primary = inPrimaryColor ? inPrimaryColor.value : '#1d4ed8';
   const sidebar = inSidebarColor ? inSidebarColor.value : '#0f172a';
   const accent = inAccentColor ? inAccentColor.value : '#f59e0b';
   const pageBg = inPageBgColor ? inPageBgColor.value : '#f8fafc';
   const cardBg = inCardBgColor ? inCardBgColor.value : '#ffffff';
   const sidebarText = inSidebarTextColor ? inSidebarTextColor.value : '#e2e8f0';
   const radius = inBorderRadius ? inBorderRadius.value : '14px';

   if (mockSidebar) {
    mockSidebar.style.background = sidebar;
    mockSidebar.querySelectorAll('.mockup-nav-item, .mockup-brand-title, small').forEach(el => {
     el.style.color = sidebarText;
    });
   }

   if (mockMain) mockMain.style.background = pageBg;
   if (mockBtnPrimary) {
    mockBtnPrimary.style.background = primary;
    mockBtnPrimary.style.borderRadius = radius;
   }
   if (mockAvatar) mockAvatar.style.background = primary;
   if (mockNavActive) {
    mockNavActive.style.borderLeftColor = accent;
    mockNavActive.style.color = '#ffffff';
   }
   if (mockCardAccent) mockCardAccent.style.color = accent;
   if (mockFrame && inFontFamily) mockFrame.style.fontFamily = inFontFamily.value;

   // Update cards inside mockup
   document.querySelectorAll('.mockup-card').forEach(card => {
    card.style.background = cardBg;
    card.style.borderRadius = radius;
   });

   // Update mockup tabs style
   if (mockTabsContainer && inTabsStyle) {
    mockTabsContainer.setAttribute('data-style', inTabsStyle.value);
   }

   // Update LED text
   if (mockUnitBadge && inBusLedText) {
    mockUnitBadge.textContent = 'UNIDAD #14 · ' + (inBusLedText.value || 'GUAYTACAMA');
   }

   // Update module icons in mockup
   const iconDash = document.getElementById('cfg-icon-dashboard');
   const titleDash = document.getElementById('cfg-title-dashboard');
   if (mockNavActive && (iconDash || titleDash)) {
    mockNavActive.textContent = (iconDash ? iconDash.value + ' ' : '▦ ') + (titleDash ? titleDash.value : 'Dashboard');
   }
  }

  function bindColorPair(colorInput, hexInput) {
   if (!colorInput || !hexInput) return;
   colorInput.addEventListener('input', () => {
    hexInput.value = colorInput.value.toUpperCase();
    updateMockup();
   });
   hexInput.addEventListener('input', () => {
    let val = hexInput.value.trim();
    if (!val.startsWith('#')) val = '#' + val;
    if (/^#[0-9A-Fa-f]{6}$/.test(val)) {
     colorInput.value = val;
     updateMockup();
    }
   });
  }

  bindColorPair(inPrimaryColor, inPrimaryHex);
  bindColorPair(inSidebarColor, inSidebarHex);
  bindColorPair(inAccentColor, inAccentHex);
  bindColorPair(inPageBgColor, inPageBgHex);
  bindColorPair(inCardBgColor, inCardBgHex);
  bindColorPair(inSidebarTextColor, inSidebarTextHex);

  if (inCompanyName) inCompanyName.addEventListener('input', updateMockup);
  if (inCompanySlogan) inCompanySlogan.addEventListener('input', updateMockup);
  if (inFooterText) inFooterText.addEventListener('input', updateMockup);
  if (inFontFamily) inFontFamily.addEventListener('change', updateMockup);
  if (inBorderRadius) inBorderRadius.addEventListener('change', updateMockup);
  if (inBusLedText) inBusLedText.addEventListener('input', updateMockup);

  // Selector de estilo de pestañas
  document.querySelectorAll('.tabs-style-option').forEach(opt => {
   opt.addEventListener('click', () => {
    document.querySelectorAll('.tabs-style-option').forEach(o => o.classList.remove('selected'));
    opt.classList.add('selected');
    const styleVal = opt.dataset.style;
    if (inTabsStyle) inTabsStyle.value = styleVal;
    updateMockup();
   });
  });

  // Selector de presets de colores
  document.querySelectorAll('.btn-preset').forEach(btn => {
   btn.addEventListener('click', () => {
    const p = btn.dataset.primary;
    const s = btn.dataset.sidebar;
    const a = btn.dataset.accent;
    const bg = btn.dataset.bg || '#f8fafc';
    if (inPrimaryColor) inPrimaryColor.value = p;
    if (inPrimaryHex) inPrimaryHex.value = p.toUpperCase();
    if (inSidebarColor) inSidebarColor.value = s;
    if (inSidebarHex) inSidebarHex.value = s.toUpperCase();
    if (inAccentColor) inAccentColor.value = a;
    if (inAccentHex) inAccentHex.value = a.toUpperCase();
    if (inPageBgColor) inPageBgColor.value = bg;
    if (inPageBgHex) inPageBgHex.value = bg.toUpperCase();
    updateMockup();
   });
  });

  // Previsualización instantánea de subida de imágenes (FileReader)
  function bindImageUploadPreview(fileInputId, previewImgId, mockupImgId, urlInputId) {
   const fileInput = document.getElementById(fileInputId);
   const previewImg = document.getElementById(previewImgId);
   const mockupImg = document.getElementById(mockupImgId);
   const urlInput = document.getElementById(urlInputId);

   if (fileInput) {
    fileInput.addEventListener('change', () => {
     const file = fileInput.files[0];
     if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
       if (previewImg) previewImg.src = e.target.result;
       if (mockupImg) mockupImg.src = e.target.result;
      };
      reader.readAsDataURL(file);
     }
    });
   }

   if (urlInput) {
    urlInput.addEventListener('input', () => {
     if (urlInput.value.trim()) {
      if (previewImg) previewImg.src = urlInput.value.trim();
      if (mockupImg) mockupImg.src = urlInput.value.trim();
     }
    });
   }
  }

  bindImageUploadPreview('cfg-header-logo-file', 'preview-header-logo', 'mockup-logo-img', 'cfg-header-logo-url');
  bindImageUploadPreview('cfg-sidebar-banner-file', 'preview-sidebar-banner', 'mockup-banner-img', 'cfg-sidebar-banner-url');
  bindImageUploadPreview('cfg-favicon-file', 'preview-favicon', null, 'cfg-favicon-url');
  bindImageUploadPreview('cfg-login-banner-file', 'preview-login-banner', null, 'cfg-login-banner-url');

  // Chips de sugerencia rápida de iconos para módulos
  document.querySelectorAll('.icon-chip').forEach(chip => {
   chip.addEventListener('click', () => {
    const targetInput = document.getElementById(chip.dataset.target);
    if (targetInput) {
     targetInput.value = chip.textContent.trim();
     updateMockup();
    }
   });
  });

  document.querySelectorAll('.module-icon-input, .module-title-input').forEach(inp => {
   inp.addEventListener('input', updateMockup);
  });

  if (btnDemoAnim && busOverlay) {
   btnDemoAnim.addEventListener('click', () => {
    const destNameEl = document.getElementById('bus-destination-name');
    if (destNameEl) destNameEl.textContent = 'Probando animación del bus...';
    busOverlay.style.display = 'flex';
    requestAnimationFrame(() => {
     busOverlay.classList.add('animating');
    });
    const dur = (parseFloat(document.getElementById('cfg-animation-duration')?.value || '1.8') || 1.8) * 1000;
    setTimeout(() => {
     busOverlay.classList.remove('animating');
     setTimeout(() => { busOverlay.style.display = 'none'; }, 250);
    }, dur);
   });
  }

  updateMockup();
 }
});
