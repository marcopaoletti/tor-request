'use strict';
var libs = {
  // communicate with SOCKS (protocol used by tor) over nodejs
  Socks: require('socks'),

  // better HTTP for nodejs
  request: require('request'),

  // promises with request hs
  rp: require('request-promise')
}

/* Run tor locally (debian example: apt-get install tor)
 * default tor ip address: localhost
 * default tor port: 9050
 *
 * links: https://www.torproject.org/docs/tor-doc-unix.html
 * */

function createProxySettings (ipaddress, port, type) {
  var dps = default_proxy_settings || {};
  var proxy_setup = {
    ipaddress: ipaddress || dps.ipaddress || "localhost", // tor address
    port: port || dps.port || 9050, // tor port
    type: type || dps.type || 5,
  };
  return proxy_setup;
}

// set default proxy settings
var default_proxy_settings = createProxySettings("localhost", 9050);

/* helper function to create a SOCKS agent to be used in the request library
 * */
function createAgent (url) {
  var proxy_setup = createProxySettings();

  var isHttps = url.indexOf('https://') >= 0;

  var socksAgent = new libs.Socks.Agent({
      proxy: proxy_setup,
    },
    isHttps, // https
    false // rejectUnauthorized option passed to tls.connect().
  );

  return socksAgent;
}


/**
 * wraps around libs.request and attaches a SOCKS Agent into
 * the request-promise.
 * @param uri
 * @param options
 * @param callback
 * @returns {Promise}
 */
function torRequest(uri, options, callback) {
  var params = libs.request.initParams(uri, options, callback);
  params.agent = createAgent(params.uri || params.url);

  return new Promise((resolve, reject) => {
    libs.rp(params)
        .then(parsedBody => resolve(parsedBody))
        .catch(err => reject(err))
        .then(() => {
          const agent = params.agent;
          if (agent && agent.encryptedSocket) {
            agent.encryptedSocket.end();
          }
        });
  });
}

// bind http through tor-request instead of request
function verbFunc(verb) {
  const method = verb === 'del' ? 'DELETE' : verb.toUpperCase();
  return function (uri, options, callback) {
    const params = libs.rp.initParams(uri, options, callback);
    params.method = method;
    return torRequest(params, params.callback);
  };
}

// create bindings through tor-request for http
torRequest.get = verbFunc('get')
torRequest.head = verbFunc('head')
torRequest.post = verbFunc('post')
torRequest.put = verbFunc('put')
torRequest.patch = verbFunc('patch')
torRequest.del = verbFunc('del')


var net = require('net'); // to communicate with the Tor clients ControlPort
var os = require('os'); // for os EOL character

// helper object for communicating with the Tor ControlPort.
// With the ControlPort we can request the Tor Client to renew out session (get new ip)
// Make sure to enable the tor ControlPort and set a password for authentication by
// running "tor --hash-password YOUR_PASSWORD_HERE"
// altogether editing two lines in your /etc/tor/torrc file.
var TorControlPort = {
  password: "", // password for ControlPort
  host: 'localhost',
  port: 9051,

  /**
   * @param {Array.<string>} commands - array of commands to send to the ControlPort
   * @param {function} done - callback function (err, data). err is null on success.
   * */
  send: function send (commands, done) {
    var socket = net.connect({
      host: TorControlPort.host || 'localhost',
      port: TorControlPort.port || 9051 // default Tor ControlPort
    }, function () {
      //console.log('connected to ControlPort!');
      var commandString = commands.join('\n') + '\n';
      socket.write( commandString );
    });

    socket.on('error', function (err) {
      done(err || 'ControlPort communication error');
    });

    var data = "";
    socket.on('data', function (chunk) {
      data += chunk.toString();
    });

    socket.on('end', function () {
      //console.log('disconncted from ControlPort');
      done(null, data);
    });
  }
};

/**
 * send a predefined set of commands to the ControlPort
 * to request a new tor session.
 * @returns {Promise}
 */
function renewTorSession () {
  return new Promise((resolve, reject) => {

    const password = TorControlPort.password || "";
    const commands = [
      'authenticate "' + password + '"', // authenticate the connection
      'signal newnym', // send the signal (renew Tor session)
      'quit' // close the connection
    ];

    TorControlPort.send(commands, function (err, data) {
      if (err) {
         reject(err);
      }
      else {
        var lines = data.split(require('os').EOL).slice(0, -1);

        var success = lines.every(function (val, ind, arr) {
          // each response from the ControlPort should start with 250 (OK STATUS)
          return val.length <= 0 || val.indexOf('250') >= 0;
        });

        if (!success) {
          reject(`Error communicating with Tor ControlPort\n ${data}`);
        } else {
          resolve('Tor session successfully renewed!!');
        }
      }
    });
  });
}

module.exports = {
  setTorAddress: function (ipaddress, port) {
    // update the default proxy settings
    default_proxy_settings = createProxySettings(ipaddress, port);
  },

  request: torRequest,
  torRequest: torRequest,

  newTorSession: renewTorSession,
  renewTorSession: renewTorSession,

  TorControlPort: TorControlPort
}
