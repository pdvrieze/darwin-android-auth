This is an authentication module that allows applications to authenticate against the challenge response authentication mechanism (code available at https://github.com/pdvrieze/ProcessManager/tree/master/accountmgr).
The library has a number of features:
* Uses public key cryptography to register a device specific key to the server
* Has its own permission request implementation to allow client apps to request permission to access the account through the intent mechanism,
  not through a notification (the default system activity causes permission errors).
