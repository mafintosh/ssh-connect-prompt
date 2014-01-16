# ssh-connect-prompt

Connect to ssh using [ssh2](https://github.com/mscdex/ssh2) and prompt stdin for host verification, key decryption etc.
Similar to what standard ssh does.

	npm install ssh-connect-prompt

## Usage

``` js
var connect = require('ssh-connect-prompt');

// c is a ssh2 connection.
var c = connect('username@example.com');

// Host verification events and passphrase input will be forwarded to the terminal as a prompt in
// a way that is similar to the regular ssh prompt

c.on('non-interactive', function() {
	console.log('No more prompts...');
});

c.on('ready', function() {
	console.log('Connection open!');
});
```

If `$SSH_AUTH_SOCK` is set it will be passed as an agent and `id_rsa` will be used as the private key per default.
When a key is verified it will be added to ~/.ssh/known_hosts - just like regular ssh

## License

MIT