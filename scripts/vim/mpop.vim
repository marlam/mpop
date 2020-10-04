" Vim syntax file
" Language:     mpop rc files
" Maintainer:   Simon Ruderich <simon@ruderich.com>
"               Eric Pruitt <eric.pruitt &amp; gmail.com>
" Last Change:  2019-09-27
" Filenames:    mpoprc
" Version:      0.3


if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif


" Comments.
syn match mpopComment /#.*$/ contains=@Spell

" General commands.
syntax match mpopOption /\<\(defaults\|account\|host\|port\|source_ip\|proxy_host\|proxy_port\|timeout\|pipelining\|uidls_file\|delivery\)\>/
" Authentication commands.
syntax match mpopOption /\<\(auth\|user\|password\|passwordeval\|ntlmdomain\)\>/
" TLS commands.
syntax match mpopOption /\<\(tls\|tls_trust_file\|tls_crl_file\|tls_fingerprint\|tls_key_file\|tls_cert_file\|tls_certcheck\|tls_starttls\|tls_min_dh_prime_bits\|tls_priorities\|tls_host_override\)\>/
" Retrieval commands.
syntax match mpopOption /\<\(only_new\|keep\|killsize\|skipsize\|filter\|received_header\)\>/

" Options which accept only an on/off value.
syn match mpopWrongOption /\<\(tls\|tls_certcheck\|tls_starttls\|only_new\|keep\|received_header\) \(on$\|off$\)\@!.*$/
" Options which accept only an on/off/auto value.
syn match mpopWrongOption /\<\(pipelining\) \(on$\|off$\|auto$\)\@!.*$/
" Options which accept numeric values.
syn match mpopWrongOption /\<\(port\|proxy_port\) \(\d\+$\)\@!.*$/
syn match mpopWrongOption /\<killsize \(\d\+$\)\@!.*$/
syn match mpopWrongOption /\<skipsize \(\d\+$\)\@!.*$/
" Option timeout accepts off and numeric values.
syn match mpopWrongOption /\<timeout \(off$\|\d\+$\)\@!.*$/
" Option auth accepts on, off and the method.
syn match mpopWrongOption /\<auth \(on$\|off$\|user$\|plain$\|cram-md5$\|digest-md5$\|scram-sha-1$\|gssapi$\|external$\|login$\|ntlm$\|oauthbearer\|xoauth2\)\@!.*$/

" Marks all wrong option values as errors.
syn match mpopWrongOptionValue /\S* \zs.*$/ contained containedin=mpopWrongOption

" Mark the option part as a normal option.
highlight default link mpopWrongOption mpopOption

"Email addresses (yanked from esmptrc)
syntax match mpopAddress /[a-z0-9_.-]*[a-z0-9]\+@[a-z0-9_.-]*[a-z0-9]\+\.[a-z]\+/
" Host names
syn match mpopHost "\%(host\s*\)\@<=\h\%(\w\|\.\|-\)*"
syn match mpopHost "\%(host\s*\)\@<=\%([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)"
" Numeric values
syn match mpopNumber /\<\(\d\+$\)/
"Strings
syntax region mpopString start=/"/ end=/"/
syntax region mpopString start=/'/ end=/'/
" Booleans
syntax match mpopBool "\s\@<=\(on\|off\)$"

highlight default link mpopComment Comment
highlight default link mpopOption Type
highlight default link mpopWrongOptionValue Error
highlight default link mpopString String
highlight default link mpopAddress Constant
highlight default link mpopNumber Number
highlight default link mpopHost Identifier
highlight default link mpopBool Constant


let b:current_syntax = "mpop"
