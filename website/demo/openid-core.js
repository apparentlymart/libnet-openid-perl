
function _OpenID_iframe_include (uri) {

    var se = document.createElement("iframe");
    se.width = 1;
    se.height = 1;
    se.style.display = 'inline';
    se.style.border = '0';

    if (0) {
	se.width = 50;
	se.height = 50;
	se.style.border = '2px solid green';
    }

    var be = document.getElementsByTagName('body').item(0);
    be.appendChild(se);
    se.contentWindow.location = uri;
}
 

// returns whether the browser is able to do the client-side version of OpenID
function OpenID_capable () {
    return getXTR() ? 1 : 0;
}


// args is object with keys:
//       client_url:   the HTML URL the client provided. is just 
//                     sent as-is to the helper URL on the server.
//       helper_url:   the URL of the helper on the server
//       on_success:   (canonical_identity_url, id_server, timestamp, sig)
//       on_error       (errtxt) general error callback
//       on_need_permissions   (url) URL to send user

function OpenID_verify (arg_hargs) {

    var xtr = getXTR();
    var nf = function () {};  // null function

    // make a copy to work around Safari bug w/ closures not capturing formal parameters
    var hargs = arg_hargs;

    // make a top-level function that captures some internal variables
    window.OpenID_callback_pass = function (identityURL, sig, timestamp) {
	(hargs.on_success||nf)(identityURL, hargs.id_server, timestamp, sig);
    };
    window.OpenID_callback_fail = function (url) {
	(hargs.on_need_permissions||nf)(url);
    };
    window.OpenID_general_error = function (erro) {
	(hargs.on_error||nf)(erro.err_code, erro.err_text);
    };

    var state_callback = function () {
	var ex;
	var helperRes;

        if (xtr.readyState != 4)
             return;

        if (xtr.status == 200) {
	    try {
		(hargs.on_debug||nf)("responseText = [" + xtr.responseText + "]");
	
		try {
		    eval("var helperRes = " + xtr.responseText + ";\n");
		} catch (ex) {
		    (hargs.on_error||nf)("invalid_json", "Got invalid JSON response from helper.  Got: " + xtr.responseText + ", e = " + ex);
		    return;
		}

		if (helperRes.err_code) {
		    (hargs.on_error||nf)(helperRes.err_code, helperRes.err_text);
		    return;
		}

		var returnTo = hargs.helper_url;
		var trustRoot = hargs.trust_root || hargs.helper_url;
		var cleanIdentityURL = helperRes.clean_identity_url;

		(hargs.on_post_helper||nf)(helperRes.id_server, cleanIdentityURL);

	        hargs.id_server = helperRes.id_server;

		_OpenID_iframe_include(helperRes.checkid_immediate_url);

	    } catch (ex) {
		(hargs.on_error||nf)("iframe_exception", "Error loading remote iframe: " + ex);
	    }
	    
        } else {
	    (hargs.on_error||nf)("helper_not_200", "Didn't get status code 200 contacting helper.  Got: " + xtr.status);
	}
	

    };

    xtr.onreadystatechange = state_callback;

    xtr.open("GET", hargs.helper_url + "&openid_url=" + escape(hargs.client_url) + "&rand=" + Math.random(), true);
    xtr.send(null);
}

function getXTR (need_req_header) {
    var xtr;
    var ex;

    if (typeof(XMLHttpRequest) != "undefined") {
	// The Firefox/Safari/Opera way
        xtr = new XMLHttpRequest();
    } else {
	// The IE way(s)

        try {
            xtr = new ActiveXObject("Msxml2.XMLHTTP.4.0");
        } catch (ex) {
            try {
                xtr = new ActiveXObject("Msxml2.XMLHTTP");
            } catch (ex) {
            }
        }
    }

    if (need_req_header) {
	    // don't work in Opera that only half-supports XMLHttpRequest
	    try {
        	    if (xtr && ! xtr.setRequestHeader)
	            xtr = null;
	    } catch (ex) { }
    }

    return xtr;
}
