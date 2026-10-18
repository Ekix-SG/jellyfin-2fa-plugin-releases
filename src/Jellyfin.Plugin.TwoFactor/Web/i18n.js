// Translations of the plugin's pages (login, manage, admin). The pages are written in Spanish; the key of every entry is
// the exact Spanish text. Languages other than Spanish get the English text (add a new language by adding a table).
// Choose the language with ?lang=es or ?lang=en; otherwise navigator.language decides ("es*" is Spanish, anything else English).
(function () {
  'use strict';

  var EN = {
    // Titles and headings
    'Iniciar sesión': 'Sign in',
    'Por favor, inicie sesión': 'Please sign in',
    'Verificación en dos pasos': 'Two-step verification',
    'Activar la verificación en dos pasos': 'Turn on two-step verification',
    'Conexión rápida': 'Quick Connect',
    'Restablecer la contraseña': 'Reset password',
    'Administrar verificación en dos pasos': 'Manage two-step verification',
    'Administrar la verificación en dos pasos': 'Manage two-step verification',

    // Login page
    'Usuario': 'User',
    'Contraseña': 'Password',
    'Recuérdame': 'Remember me',
    'Usar conexión rápida': 'Use Quick Connect',
    'Contraseña olvidada': 'Forgot password',
    'Cambiar servidor': 'Change server',
    'En un dispositivo donde ya hayas iniciado sesión (con verificación en dos pasos), abre el menú de usuario, elige':
      'On a device where you are already signed in (with two-step verification), open the user menu, choose',
    'e introduce este código:': 'and enter this code:',
    'Esperando autorización…': 'Waiting for authorization…',
    'Autorizado. Entrando…': 'Authorized. Signing in…',
    'Cancelar': 'Cancel',
    'Generar PIN': 'Generate PIN',
    'Generar PIN de nuevo': 'Generate PIN again',
    'PIN': 'PIN',
    'Nueva contraseña': 'New password',
    'Repite la nueva contraseña': 'Repeat the new password',
    'Cambiar contraseña': 'Change password',
    'Volver': 'Back',
    'Introduce el código que muestra tu aplicación de autenticación.': 'Enter the code shown by your authenticator app.',
    'Código': 'Code',
    'Escanea este código QR con tu aplicación de autenticación (o introduce la clave a mano) y escribe el código que te muestre.':
      'Scan this QR code with your authenticator app (or enter the key by hand) and type the code it shows.',
    'Código de invitación': 'Invitation code',
    'Para activar la verificación en dos pasos necesitas un código de invitación que te da un administrador del servidor.':
      'To turn on two-step verification you need an invitation code that a server administrator gives you.',
    'Continuar': 'Continue',
    'Activar y entrar': 'Turn on and sign in',
    'Empezar de nuevo': 'Start over',
    'Código QR': 'QR code',
    'Credenciales o código incorrectos.': 'Wrong credentials or code.',
    'Se ha generado un PIN. Jellyfin lo ha guardado en el servidor': 'A PIN has been generated. Jellyfin saved it on the server',
    'fichero': 'file',
    'y caduca en 30 minutos; solo es válido si pides el PIN desde la red local.':
      'and it expires in 30 minutes; it is only valid if you request the PIN from the local network.',
    'Léelo en el servidor y escríbelo aquí.': 'Read it on the server and type it here.',
    'No se ha podido generar el PIN.': 'The PIN could not be generated.',
    'Las dos contraseñas deben coincidir y no pueden estar vacías.': 'The two passwords must match and cannot be empty.',
    'Contraseña cambiada. Entra con tu nueva contraseña y el código de tu aplicación de autenticación.':
      'Password changed. Sign in with your new password and the code from your authenticator app.',
    'PIN incorrecto o caducado.': 'Wrong or expired PIN.',
    'PIN o contraseña no válidos.': 'Invalid PIN or password.',
    'No se ha podido cambiar la contraseña.': 'The password could not be changed.',

    // Manage page
    'Para dar de alta otra aplicación de autenticación (por ejemplo, un móvil nuevo), confirma tu contraseña. El autenticador actual seguirá valiendo hasta que confirmes el nuevo.':
      'To register another authenticator app (for example, a new phone), confirm your password. The current authenticator stays valid until you confirm the new one.',
    'Escanea este código QR con la aplicación de autenticación nueva (o introduce la clave a mano) y escribe el código que te muestre.':
      'Scan this QR code with the new authenticator app (or enter the key by hand) and type the code it shows.',
    'Cerrar mis otras sesiones (recomendado si has perdido el móvil)': 'Sign out my other sessions (recommended if you lost your phone)',
    'Sustituir el autenticador': 'Replace the authenticator',
    'Listo. El autenticador nuevo ya está activo y el anterior deja de valer.': 'Done. The new authenticator is active and the old one no longer works.',
    'Tus otras sesiones se han cerrado.': 'Your other sessions have been signed out.',
    'No se han podido cerrar tus otras sesiones.': 'Your other sessions could not be signed out.',
    'Volver al servidor': 'Back to the server',
    'Contraseña o código incorrectos.': 'Wrong password or code.',

    // Admin page
    'Esta página es solo para administradores.': 'This page is for administrators only.',
    '«Reiniciar autenticador» borra el autenticador del usuario: en su próximo inicio de sesión tendrá que dar de alta uno nuevo. Cierra todas sus sesiones abiertas y no cambia su contraseña.':
      '"Reset authenticator" deletes the user\'s authenticator: at their next sign-in they will have to register a new one. It signs out all their open sessions and does not change their password.',
    'Reiniciar autenticador': 'Reset authenticator',
    '¿Reiniciar el autenticador de': 'Reset the authenticator of',
    'Tendrá que dar de alta uno nuevo en su próximo inicio de sesión.': 'They will have to register a new one at their next sign-in.',
    'reiniciado.': 'was reset.',
    'no tenía autenticador dado de alta.': 'had no authenticator registered.',
    'No se ha podido reiniciar el autenticador de': 'The authenticator could not be reset for',
    'Autenticador de': 'Authenticator of',
    'Un usuario sin autenticador necesita un': 'A user without an authenticator needs an',
    'código de invitación': 'invitation code',
    'para darlo de alta: genéralo aquí y entrégaselo por un canal seguro. Se muestra una sola vez, sirve una sola vez y caduca. «Reiniciar autenticador» borra el del usuario (cierra sus sesiones y no cambia su contraseña).':
      'to register one: generate it here and hand it over through a secure channel. It is shown once, works once and expires. "Reset authenticator" deletes the user\'s one (it signs out their sessions and does not change their password).',
    'Inscrito': 'Enrolled',
    'Sin inscribir': 'Not enrolled',
    'Sin inscribir; código vigente hasta': 'Not enrolled; code valid until',
    'Generar código': 'Generate code',
    'Revocar código': 'Revoke code',
    'Código de': 'Code for',
    'válido hasta': 'valid until',
    'revocado.': 'was revoked.',
    'No se ha podido generar el código de': 'The code could not be generated for',
    'No se ha podido revocar el código de': 'The code could not be revoked for'
  };

  var requested = /[?&]lang=([a-z]{2})\b/i.exec(location.search);
  var code = requested ? requested[1].toLowerCase() : String(navigator.language || 'es').slice(0, 2).toLowerCase();
  var english = code !== 'es';

  // Translates a Spanish text; unknown texts and Spanish readers get the text as it is.
  function t(text) {
    return english && Object.prototype.hasOwnProperty.call(EN, text) ? EN[text] : text;
  }

  function translateNodes(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var nodes = [];
    while (walker.nextNode()) { nodes.push(walker.currentNode); }
    nodes.forEach(function (node) {
      var parent = node.parentNode;
      if (parent && /^(SCRIPT|STYLE)$/i.test(parent.nodeName)) { return; }
      var trimmed = node.nodeValue.trim();
      if (trimmed && Object.prototype.hasOwnProperty.call(EN, trimmed)) {
        node.nodeValue = node.nodeValue.replace(trimmed, EN[trimmed]);
      }
    });
    root.querySelectorAll('[aria-label],[title],[placeholder]').forEach(function (element) {
      ['aria-label', 'title', 'placeholder'].forEach(function (name) {
        if (element.hasAttribute(name)) { element.setAttribute(name, t(element.getAttribute(name))); }
      });
    });
  }

  function apply() {
    if (!english) { return; }
    document.documentElement.lang = code;
    document.title = t(document.title);
    translateNodes(document.body);
  }

  window.tfI18n = { t: t, apply: apply, isEnglish: english, strings: EN };
  apply();
})();
