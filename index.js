var Connection = require('ssh2');
var once = require('once');
var fs = require('fs');
var path = require('path');
var readline = require('readline');
var crypto = require('crypto');
var read = require('read');

var noop = function() {};

var HOME = process.env.HOME || process.env.USERPROFILE;
var SSH_HOME = path.join(HOME, '.ssh');

var KNOWN_HOSTS;
var ID_RSA;

try {
	ID_RSA = fs.readFileSync(path.join(SSH_HOME, 'id_rsa'));
} catch (err) {
	ID_RSA = null;
}

try {
	KNOWN_HOSTS = fs.readFileSync(path.join(SSH_HOME, 'known_hosts'), 'utf-8').trim().split('\n');
} catch (err) {
	KNOWN_HOSTS = [];
}

var KNOWN_HOSTS_MAP = KNOWN_HOSTS.reduce(function(result, entry) {
	var i = entry.indexOf(' ');
	entry.slice(0, i).split(',').forEach(function(k) {
		result[k] = entry.slice(i+1);
	});
	return result;
}, {});

var encrypted = function(pem) {
	return pem && pem.indexOf('ENCRYPTED') > -1;
};

var oninteractive = function(c) {
	c.on('verify', function(key, opts, cb) {
		process.stderr.write(
			'The authenticity of host \''+opts.host+'\' can\'t be established.\n'+
			'RSA key fingerprint is '+opts.fingerprint.replace(/(..)/g, '$1:').slice(0, -1)+'.\n'
		);

		var save = function() {
			fs.mkdir(SSH_HOME, function() {
				fs.appendFile(path.join(SSH_HOME, 'known_hosts'), opts.host+' '+key+'\n', function() {
					cb();
				});
			});
		};

		read({prompt: 'Are you sure you want to continue connecting (yes/no)? '}, function onanswer(err, answer) {
			if (err) return cb(err);
			if (answer === 'no') return cb(new Error('Could not verify host key'));
			if (answer === 'yes') return save();
			read({prompt:'Please type \'yes\' or \'no\': '}, onanswer);
		});
	});

	c.on('decrypt', function(key, opts, cb) {
		read({
			prompt: 'Enter passphrase for key'+(opts.filename ? ' \''+opts.filename+'\': ' : ': '),
			silent: true,
			output: process.stderr
		}, cb);
	});
};

var connect = function(host, opts, cb) {
	if (typeof host === 'object' && host) return connect(null, host, opts);
	if (typeof opts === 'function') return connect(host, null, opts);
	if (!opts) opts = {};
	if (!cb) cb = cb;

	var c = new Connection();
	var key = opts.privateKey || opts.key;
	var entry = '';

	if (opts.interactive !== false) oninteractive(c);

	host = host.match(/^(?:([^@]+)@)?([^:]+)(?::(\d+))?/);
	cb = once(cb || noop);

	opts.username = host[1] || 'root';
	opts.host = host[2];
	opts.port = parseInt(host[3] || 22, 10);
	opts.agent = opts.agent !== false && process.env.SSH_AUTH_SOCK;
	opts.privateKey = key;

	var knownHost = opts.verify !== false && KNOWN_HOSTS_MAP[opts.host];
	var listeners = c._parser.listeners('USERAUTH_SUCCESS');
	var entry;
	var fingerprint;

	var onerror = function(err) {
		c.emit('error', err);
		c.end();
	};

	c._parser.on('KEXDH_REPLY', function(info) {
		fingerprint = crypto.createHash('md5').update(info.hostkey).digest('hex');
		entry = info.hostkey_format+' '+info.hostkey.toString('base64');
	});

	c._parser.removeAllListeners('USERAUTH_SUCCESS');
	c._parser.on('USERAUTH_SUCCESS', function(info) {
		var next = function(err) {
			if (err) return onerror(err);

			if (!knownHost) c.emit('non-interactive');

			listeners.forEach(function(fn) {
				fn.call(c, info);
			});
		};

		if (knownHost) return next(knownHost !== entry && new Error('Known host does not match fingerprint'));
		if (!c.emit('verify', entry, {fingerprint:fingerprint, host:opts.host, username:opts.username}, next)) next();
	});

	if (!opts.privateKey && ID_RSA && (!opts.agent || !encrypted(ID_RSA))) opts.privateKey = ID_RSA;

	var onkey = function(filename) {
		if (!opts.privateKey) return c.connect(opts);
		if (!encrypted(opts.privateKey.toString())) return c.connect(opts);
		if (opts.passphrase) return c.connect(opts);

		var next = function(err, passphrase) {
			if (err) return onerror(err);
			opts.passphrase = passphrase;
			if (knownHost) c.emit('non-interactive');
			c.connect(opts);
		};

		if (!c.emit('decrypt', opts.privateKey.toString(), {filename:filename}, next)) next();
	};

	if (typeof opts.privateKey !== 'string') {
		onkey();
		return c;
	}

	var filename = opts.privateKey.replace(/^~/, HOME);

	fs.readFile(filename, function(_, buf) {
		opts.privateKey = buf;
		onkey(filename);
	});

	return c;
};

module.exports = connect;