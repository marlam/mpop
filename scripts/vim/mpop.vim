" Vim syntax file
" Language:     mpop rc files
" Maintainer:   Simon Ruderich <simon@ruderich.com>
" Last Change:  2008-12-24
" Filenames:    mpoprc
" Version:      0.1


if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif


" Comments.
syn match mpopComment /#.*$/ contains=@Spell

" General commands.
syntax match mpopOption /\<\(defaults\|account\|host\|port\|timeout\|pipelining\|uidls_file\|delivery\)\>/
" Authentication commands.
syntax match mpopOption /\<\(auth\|user\|password\|ntlmdomain\)\>/
" TLS commands.
syntax match mpopOption /\<\(tls\|tls_trust_file\|tls_crl_file\|tls_fingerprint\|tls_key_file\|tls_cert_file\|tls_certcheck\|tls_starttls\|tls_force_sslv3\|tls_min_dh_prime_bits\|tls_priorities\)\>/
" Retrieval commands.
syntax match mpopOption /\<\(only_new\|keep\|killsize\|skipsize\|filter\)\>/


" Options which accept only an on/off value.
syn match mpopWrongOption /\<\(tls\|tls_certcheck\|tls_starttls\|tls_force_sslv3\|only_new\|keep\) \(on$\|off$\)\@!.*$/
" Options which accept only an on/off/auto value.
syn match mpopWrongOption /\<\(pipelining\) \(on$\|off$\|auto$\)\@!.*$/
" Options which accept numeric values.
syn match mpopWrongOption /\<port \(\d\+$\)\@!.*$/
syn match mpopWrongOption /\<killsize \(\d\+$\)\@!.*$/
syn match mpopWrongOption /\<skipsize \(\d\+$\)\@!.*$/
" Option timeout accepts off and numeric values.
syn match mpopWrongOption /\<timeout \(off$\|\d\+$\)\@!.*$/
" Option auth accepts on, off and the method.
syn match mpopWrongOption /\<auth \(on$\|off$\|user$\|plain$\|cram-md5$\|digest-md5$\|scram-sha-1$\|gssapi$\|external$\|login$\|ntlm$\)\@!.*$/

" Marks all wrong option values as errors.
syn match mpopWrongOptionValue /\S* \zs.*$/ contained containedin=mpopWrongOption

" Mark the option part as a normal option.
highlight default link mpopWrongOption mpopOption

highlight default link mpopComment Comment
highlight default link mpopOption Type
highlight default link mpopWrongOptionValue Error

let b:current_syntax = "mpop"
