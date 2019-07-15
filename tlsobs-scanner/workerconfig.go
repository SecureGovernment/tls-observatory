package main

import (
	_ "github.com/SecureGovernment/tls-observatory/worker/awsCertlint"
	_ "github.com/SecureGovernment/tls-observatory/worker/caaWorker"
	_ "github.com/SecureGovernment/tls-observatory/worker/crlWorker"
	_ "github.com/SecureGovernment/tls-observatory/worker/dnsWorker"
	_ "github.com/SecureGovernment/tls-observatory/worker/evCheckerWorker"
	_ "github.com/SecureGovernment/tls-observatory/worker/mozillaEvaluationWorker"
	_ "github.com/SecureGovernment/tls-observatory/worker/mozillaGradingWorker"
	_ "github.com/SecureGovernment/tls-observatory/worker/ocspStatus"
	_ "github.com/SecureGovernment/tls-observatory/worker/sslLabsClientSupport"
	_ "github.com/SecureGovernment/tls-observatory/worker/symantecDistrust"
	_ "github.com/SecureGovernment/tls-observatory/worker/top1m"
)
