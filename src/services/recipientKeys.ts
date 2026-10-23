/**
 * TrustRoot Mobile - Recipient Key Registry
 * Configured recipient public keys for hybrid payload encryption.
 *
 * SECURITY NOTICE:
 * In production UIDAI or enterprise deployments, only the Recipient Public Key / X.509 Certificate
 * is provisioned to client devices.
 * The test private keys below are STRICTLY ISOLATED to the Verification Lab test harness
 * to demonstrate mathematical correctness, tampering detection, and authenticated decryption offline.
 */

import { RecipientKeyInfo } from '../types/security';
import { sha256Hex } from '../utils/cryptoUtils';

export const RECIPIENT_PRIMARY_TEST: RecipientKeyInfo = {
  keyId: 'rcpt_uidai_test_2026',
  label: 'UIDAI Offline Demo Recipient (RSA-2048)',
  organization: 'UIDAI Hackathon Evaluation Environment',
  algorithm: 'RSA_2048',
  keyWrappingAlgorithm: 'RSA-OAEP-SHA256',
  isTestKey: true,
  fingerprintSha256: 'B6:7A:41:48:97:93:2A:44:8D:1F:19:D8:F8:78:8F:D6',
  publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuImk19kMlmoD8QqT6XHo
s2fg4dYeJrmR/s8J6S5yUtNPjkjOf0rO/cyJEjbDGZXkbXDD9A4Ukk1mUSSMl2hs
1XRENg6LvtgGizg1nhM3MN31SzaK0Jla50Jh+cr02FWBPLNlAMiYYF5QtSk2TAG+
QTY47tx14JnveuViRgs4qqE8Gojgr4c8XwGvgRCDB0kvX1sP7qzLIRD27dG5Yo/y
tFFePkvR+BceD6zJhrCWCrjFgFCPMRCQQAG2pGfLn+IcUBa21C0A/ooA6x1Bj6MH
pYPm7ZkbCGjKYFIVVwNWwZJ0znIDbi8xCR8IV5sgDjgEOtsQ/bfFCi3Xd3psmqrs
vQIDAQAB
-----END PUBLIC KEY-----`
};

export const RECIPIENT_SECONDARY_TEST: RecipientKeyInfo = {
  keyId: 'rcpt_sandbox_partner_2026',
  label: 'Sandbox Partner Verifier (RSA-2048)',
  organization: 'MeitY Sandbox Validation Lab',
  algorithm: 'RSA_2048',
  keyWrappingAlgorithm: 'RSA-OAEP-SHA256',
  isTestKey: true,
  fingerprintSha256: '4E:82:5D:8B:11:F5:2B:60:88:AC:61:A0:D3:5F:79:3E',
  publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo7IrvE0/2NOT+Uk2Xh8W
zOBSpwOdfso256NY6FXam5haU0aLR6nUNkdDf0aPqHq+ofCQLIEOCZU+rcey+iAE
WL9V26/yFEzs/Xe4QmPBGlTOI0935HxLg1iitYOGSJOn0MOlgt1xPCwUKp55ksFg
e35t+rVmnIIxpbJl7TAAbnAudwW4nHoIe3D17ViqptVfN9GsOrxNKp2VeyUp5M9C
dk+EP32ejG2dzfrzXofgEhAvszS2eRLObZSjUdTtbFNuaHPnbYGI+a5Evk5AC8mR
2wxiXJNR3Of35hzZjN72y9JKOLBcD4gOhpPO2ULsxB5bLDN6SkVYmHAia3oiZbLA
lQIDAQAB
-----END PUBLIC KEY-----`
};

export const AVAILABLE_RECIPIENTS: RecipientKeyInfo[] = [
  RECIPIENT_PRIMARY_TEST,
  RECIPIENT_SECONDARY_TEST
];

/**
 * TEST HARNESS ONLY:
 * Corresponding private keys strictly used by the offline Verification Lab.
 * Never bundled or exposed in production deployment builds.
 */
export const TEST_ONLY_RECIPIENT_PRIVATE_KEYS: Record<string, string> = {
  'rcpt_uidai_test_2026': `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC4iaTX2QyWagPx
CpPpceizZ+Dh1h4muZH+zwnpLnJS00+OSM5/Ss79zIkSNsMZleRtcMP0DhSSTWZR
JIyXaGzVdEQ2Dou+2AaLODWeEzcw3fVLNorQmVrnQmH5yvTYVYE8s2UAyJhgXlC1
KTZMAb5BNjju3HXgme965WJGCziqoTwaiOCvhzxfAa+BEIMHSS9fWw/urMshEPbt
0blij/K0UV4+S9H4Fx4PrMmGsJYKuMWAUI8xEJBAAbakZ8uf4hxQFrbULQD+igDr
HUGPowelg+btmRsIaMpgUhVXA1bBknTOcgNuLzEJHwhXmyAOOAQ62xD9t8UKLdd3
emyaquy9AgMBAAECggEAEMG27T6xTOs9hmK+gaEtTzUsj3VA8aVCI5ArRzhHe0vi
2nmz/o0NdLBg9f1xA96/ikyGDqBEr/BFTTLzbUA3Ob6//uSdPewh0/x7qen2xgIx
pu3B9yUlwwAdI3CRgR9qh9eGYWbVp1KJI5olawtxejxxOQdd0NJJk7BGlzOnpp6r
/CsQ+CU60ZF/mec6lr20TRzNGpyB3LPVJRVAQhpOtT2yoAmjArztsd6m0r3xBpzu
6/iUwWeSlHNp4Bp4JqtPIHNeud12H0J/a2dRppo8WV0eMzimQHQccntMbL+SfyfG
nu01iZnfNxFXSGul5nwBm7KrljdKJE+UxjDlQDeA4QKBgQDasbYC3SaKXq9u6sc/
2rVVZIJT7hOp0H7biBnOUsr/F4xEfC/M+sRc8i7nNJl7F4k0IgrR+sFe3+GnE0Ud
A5LwdddNW0TqW9E9Qx9hICLfsRAxQyiEtRKnoYPR2ETN6zUy2cZ2tf0ZUAkOTAwu
yu7qyo7yUofIh3n8M/n/Y9Fj6QKBgQDYBFTcZKFaVtweHMSH4Akz5TREcAgNmn0e
7a5lhMEAiYX/vmYNJZc4aaljcZbr81EOS+zVLHy04WUBLTufHj8taVje/L+m7hAE
vyWJdOH7JbsCWiy6PbnQCg4bOm6Ntcm3MUouFo88CGMXx+Tg6Qmv151TU93DfGQN
8ttvBCRhtQKBgQCndWLAyKTFWYGONjrCG2+05pShPfFSm/M3mPzhryX/tQFUQ5+6
nt6TqWLe6bkIt1n5UIPmi9NcGaTJcYj/kYgHlsR5WITpy8rp1ScHETuC/CtA/YLe
M2UIdTXiDm+JGi0PNhCxP+OBaXa1uuetQPk3UkmpJicRFyQCSa6Jr95bWQKBgQCx
rg5nIdaeSifQFPWKlbq8FuGBEW1uUw5rrDDwi9t8p6GylFe4pJzX6AFOLJZpCcA4
NDdfuLHyzhqYdy49WVG59pcFA3xYwCQo41jq0Vs3ivdhne6AWllGR58Gwm9A3LBI
oKBVfHTgej2Xx/H5FXXET2O2sJsOOnjKCGJ51DxgqQKBgQChrhAQMuPWgI9+R4cx
RVVxkmBkvuhs+SctoFdM72nESysxYGgWM+AJD0YsqLULgjFbPwDR8yn14EvQI91G
CX2ZeXJCWxPoVXm7cXjJgxpOCg3CN45FANjEz2JUkjHiRc2RWbSMkY/SDgXUY4sV
jDXU1OUdbX2Du3Lix0xgOJTiSw==
-----END PRIVATE KEY-----`,

  'rcpt_sandbox_partner_2026': `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCjsiu8TT/Y05P5
STZeHxbM4FKnA51+yjbno1joVdqbmFpTRotHqdQ2R0N/Ro+oer6h8JAsgQ4JlT6t
x7L6IARYv1Xbr/IUTOz9d7hCY8EaVM4jT3fkfEuDWKK1g4ZIk6fQw6WC3XE8LBQq
nnmSwWB7fm36tWacgjGlsmXtMABucC53Bbicegh7cPXtWKqm1V830aw6vE0qnZV7
JSnkz0J2T4Q/fZ6MbZ3N+vNeh+ASEC+zNLZ5Es5tlKNR1O1sU25oc+dtgYj5rkS+
TkALyZHbDGJck1Hc5/fmHNmM3vbL0ko4sFwPiA6Gk87ZQuzEHlssM3pKRViYcCJr
eiJlssCVAgMBAAECggEAA3zHLZx0j7E3Y5zZnQa4rNhImn/bSguTQN+pzU59OSWH
kNDCSUwQKGeWsXeI3vinC3qYwgH3R/Npqu9objniiUAPbbTzrft3kVqMqi3+Thxg
RVIrBl0yrcpSRIQhUFGEavTRPDtIgadQLdEe7YGvTnSCllAgCkyNM8tJrsIkrxEJ
SaErKolhZcPXHTAJGPOGR51wWQvtZ4IjiNZ2ORAc6WqNkFh+Us1ESvZ0Ok3EnerE
z9IuUzd9NPuQLKbXdEkm4t/m6H3pWJC0P2Mc+6Z9wcjX/j7nhtWT4nzrr8V8tyfZ
k7nu4cXKEEgM1jD6ZeN6x1RlGF+wb2TXeorj8Z3V0QKBgQDh/uIfdlb63QcTyXaB
XppEKsqrnSib5RRCe+yX6IK3F1srdSdSj0uaI6Irc/2ZFCls1HDzdtrEdI3pSFJe
E51bgFbuEAJGlaUAw/E+40lOyxTKHV3wZGLGOqYbyCUztqF+BiQ1ZKVyCsJWiAGJ
QDi61//SYj9wB3yG+AmLPU6c/QKBgQC5bdpmN8GnCEhTZRBuiiMR/RaEAPFrx5Cm
hL3sFfxEQ5ARzIo4XkfBK8ZgwlI2SSz4OPZrQPWt3ojdisH+ZVEh+d8r7LPfQOOE
G8xgPm307f028txdhjNCtaZABMM1BgacKHlqhdRhCcPT7GSTfIhtFy3NZ7cuKNxz
FQYhYODReQKBgFm7wMFJVcQKGxNKPRmlHI/QheSaZFNyJBc56Xlvwuc8COE6hUCM
0TIE0BF83sb3cHNb7vVczgSPWwGzy7C7DRIV5W5lQOIR7RBevN2BlcwJatnNy0z2
LxoSk34YfF0KORk3Cw2ARwj/KKb/Hc0HiP73YQaCKDotXs6gkfmNgDdpAoGBAKAu
u6ntpIZMa15PQeCbyCvz/A1QWz2GCfkvVnmpjGDUFJKrpQOIvmerDxXrB+YJVKWh
X43LcfAe+xCWm3rNv0ageh+RvNixT1mCQg0qIQaiyEk9hwvrsECCdvl6o78cU312
oVxZ+9tP+jEKVt/phljm2xRD8kQX3Eg18zPGYq/RAoGAVpZBVI2Cz+ftl5tV8p5z
iY4dstZcgq2tB91xOsTarhB4KnCuvuQ5YwD6CqcMRRkg2BPtQKivTyQe4HCDJ0QJ
USF4vy7jmYMLvBbLSqbMwiRhiFFuOVU3SqwHCtPNtX83jkcS8S4fZZ5rivHnN06+
dBPjHtFT/P3dcbyH6qBGSM0=
-----END PRIVATE KEY-----`
};
