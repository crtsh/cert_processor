package certwatch

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/crtsh/cert_processor/config"
	"github.com/crtsh/cert_processor/logger"

	x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jackc/pgx/v5"

	"go.uber.org/zap"
)

type certURLRecord struct {
	issuerCAID         int32
	firstCertificateID int64
}

type certRecord struct {
	certID     int64
	issuerCAID int32
	notAfter   time.Time
	numIndex   int
}

type caUpdateRecord struct {
	caID              int32
	numIssuedC        int
	numIssuedP        int
	numExpiredC       int
	numExpiredP       int
	lastNotAfter      sql.NullTime
	nextNotAfter      sql.NullTime
	lastCertificateID int64
}

func CertProcessor(ctx context.Context) {
	logger.Logger.Info("Started CertProcessor")

	nextExpireCerts_time := time.Now()
	nextProcessCerts_time := time.Now()

	for {
		select {
		// Process a batch of certs, then fire a timer when it's time to process some more.
		case <-time.After(time.Until(nextProcessCerts_time)):
			nextProcessCerts_time = time.Now().Add(processCerts())
		case <-time.After(time.Until(nextExpireCerts_time)):
			nextExpireCerts_time = time.Now().Add(expireCerts())
		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			ShutdownWG.Done()
			logger.Logger.Info("Stopped CertProcessor")
			return
		}
	}
}

func expireCerts() time.Duration {
	var newExpirations, casAffected int64
	minLastNotAfter := &time.Time{}
	var err error

	if err = connCertProcessor.QueryRow(context.Background(), "SELECT * FROM process_expirations()").Scan(&newExpirations, &casAffected, &minLastNotAfter); err != nil {
		LogPostgresError(err)
		return config.Config.Expirer.RetryAfterErrorFrequency
	} else {
		if (newExpirations > 0) || (casAffected > 0) {
			logger.Logger.Info(
				"Expirations Processed",
				zap.Int64("new_expirations", newExpirations),
				zap.Int64("cas_affected", casAffected),
				zap.Timep("min_last_not_after", minLastNotAfter),
			)
			return 0
		} else {
			return config.Config.Expirer.BatchFrequency
		}
	}
}

func processCerts() time.Duration {
	var tx pgx.Tx
	var rows pgx.Rows
	var err error
	var maxLastCertificateID, startCertificateID, endCertificateID, latestCertificateID, certificateID, numCerts int64
	var issuerCAID int32
	var derCertificate []byte
	certs := make([]certRecord, 0)
	unparsableCerts := make([]int64, 0)
	cdpURLs := make(map[string]certURLRecord)
	ocspURLs := make(map[string]certURLRecord)
	caiURLs := make(map[string]certURLRecord)
	certURLsToImport := [][]any{}
	caMap := make(map[int32]caUpdateRecord)
	caIDs := make([]int32, 0)
	caUpdates := [][]any{}

	// Start a transaction.
	if tx, err = connCertProcessor.Begin(context.Background()); err != nil {
		goto done
	}
	defer tx.Rollback(context.Background())

	// Determine the range of certificate IDs to process in this batch.
	if err = tx.QueryRow(context.Background(), `
SELECT coalesce(max(ca.LAST_CERTIFICATE_ID), 0)
	FROM ca
`).Scan(&maxLastCertificateID); err != nil {
		goto done
	}

	if err = tx.QueryRow(context.Background(), `
SELECT greatest(min(c.ID), $1 + 1)
	FROM certificate c
	WHERE c.ID > $1
`, maxLastCertificateID).Scan(&startCertificateID); err != nil {
		goto done
	}

	if err = tx.QueryRow(context.Background(), `
SELECT coalesce(max(c.ID), 0)
	FROM certificate c
`).Scan(&latestCertificateID); err != nil {
		goto done
	}

	if latestCertificateID < startCertificateID {
		return config.Config.Processor.BatchFrequency // No more work to do right now.
	} else if latestCertificateID > (startCertificateID + int64(config.Config.Processor.MaxBatchSize) - 1) {
		endCertificateID = startCertificateID + int64(config.Config.Processor.MaxBatchSize) - 1
	} else {
		endCertificateID = latestCertificateID
	}

	// Get the batch of certificates.
	if rows, err = tx.Query(context.Background(), `
SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE
	FROM certificate c
	WHERE c.ID BETWEEN $1 AND $2
`, startCertificateID, endCertificateID); err != nil {
		goto done
	}
	defer rows.Close()
	for rows.Next() {
		// Get a certificate.
		if err = rows.Scan(&certificateID, &issuerCAID, &derCertificate); err != nil {
			goto done
		}

		// Parse the certificate.
		numCerts++
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(derCertificate); x509.IsFatal(err) {
			logger.Logger.Warn(
				"ParseCertificate() failed",
				zap.Error(err),
				zap.Int64("certificate_id", certificateID),
			)
			// We'll do another parsing attempt after this loop, using libx509pq/OpenSSL.
			unparsableCerts = append(unparsableCerts, certificateID)

		} else {
			if err != nil {
				logger.Logger.Info(
					"ParseCertificate() failed (non-fatal)",
					zap.Error(err),
					zap.Int64("certificate_id", certificateID),
				)
			}

			// Add this cert to the slice of certs.
			certs = append(certs, certRecord{
				certID:     certificateID,
				issuerCAID: issuerCAID,
				notAfter:   cert.NotAfter,
				numIndex:   numIndex(cert),
			})
			// Add this cert's issuing CA to the map of "ca" records that will need to be updated.
			if _, ok := caMap[issuerCAID]; !ok {
				caMap[issuerCAID] = caUpdateRecord{caID: issuerCAID}
			}

			// Deduplicate the CDP and AIA URLs found in these certificates.
			for _, url := range cert.CRLDistributionPoints {
				url := strings.TrimSpace(url)
				if cur, ok := cdpURLs[url]; !ok {
					cdpURLs[url] = certURLRecord{issuerCAID: issuerCAID, firstCertificateID: certificateID}
				} else if certificateID < cur.firstCertificateID {
					cur.firstCertificateID = certificateID
					cdpURLs[url] = cur
				}
			}
			for _, url := range cert.OCSPServer {
				url := strings.TrimSpace(url)
				if cur, ok := ocspURLs[url]; !ok {
					ocspURLs[url] = certURLRecord{issuerCAID: issuerCAID, firstCertificateID: certificateID}
				} else if certificateID < cur.firstCertificateID {
					cur.firstCertificateID = certificateID
					ocspURLs[url] = cur
				}
			}
			for _, url := range cert.IssuingCertificateURL {
				url := strings.TrimSpace(url)
				if cur, ok := caiURLs[url]; !ok {
					caiURLs[url] = certURLRecord{issuerCAID: issuerCAID, firstCertificateID: certificateID}
				} else if certificateID < cur.firstCertificateID {
					cur.firstCertificateID = certificateID
					caiURLs[url] = cur
				}
			}
		}
	}
	rows.Close() // Don't wait for the deferred Close() when we can close it now.

	// Use libx509pq/OpenSSL to attempt to parse any certs that Go could not parse.
	for _, certID := range unparsableCerts {
		cr := certRecord{certID: certID}
		if err = tx.QueryRow(context.Background(), `
SELECT c.ISSUER_CA_ID, coalesce(nullif(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp), '1970-01-01'::date),
		CASE WHEN x509_hasExtension(c.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', TRUE) THEN 2 ELSE 1 END
	FROM certificate c
	WHERE c.ID = $1
`, cr.certID).Scan(&cr.issuerCAID, &cr.notAfter, &cr.numIndex); err != nil {
			goto done
		}
		// Add this cert to the slice of certs.
		certs = append(certs, cr)
		// Add this cert's issuing CA to the map of "ca" records that will need to be updated.
		if _, ok := caMap[cr.issuerCAID]; !ok {
			caMap[cr.issuerCAID] = caUpdateRecord{caID: cr.issuerCAID}
		}
		// Extract the CDP and AIA URLs from this certificate.
		if rows, err = tx.Query(context.Background(), `
SELECT x509_crlDistributionPoints(c.CERTIFICATE), 0
	FROM certificate c
	WHERE c.ID = $1
UNION
SELECT x509_authorityInfoAccess(c.CERTIFICATE, 1), 1
	FROM certificate c
	WHERE c.ID = $1
UNION
SELECT x509_authorityInfoAccess(c.CERTIFICATE, 2), 2
	FROM certificate c
	WHERE c.ID = $1
`, cr.certID); err != nil {
			goto done
		}
		defer rows.Close()
		for rows.Next() {
			var url string
			var urlType int
			if err = rows.Scan(&url, &urlType); err != nil {
				goto done
			}
			url = strings.TrimSpace(url)
			// Deduplicate the CDP and AIA URLs found in this certificate.
			switch urlType {
			case 0:
				if cur, ok := cdpURLs[url]; !ok {
					cdpURLs[url] = certURLRecord{issuerCAID: issuerCAID, firstCertificateID: certificateID}
				} else if certificateID < cur.firstCertificateID {
					cur.firstCertificateID = certificateID
					cdpURLs[url] = cur
				}
			case 1:
				if cur, ok := ocspURLs[url]; !ok {
					ocspURLs[url] = certURLRecord{issuerCAID: issuerCAID, firstCertificateID: certificateID}
				} else if certificateID < cur.firstCertificateID {
					cur.firstCertificateID = certificateID
					ocspURLs[url] = cur
				}
			case 2:
				if cur, ok := caiURLs[url]; !ok {
					caiURLs[url] = certURLRecord{issuerCAID: issuerCAID, firstCertificateID: certificateID}
				} else if certificateID < cur.firstCertificateID {
					cur.firstCertificateID = certificateID
					caiURLs[url] = cur
				}
			}
		}
	}

	// Create a temporary table to assist with adding newly discovered CDP and AIA URLs.
	if _, err = tx.Exec(context.Background(), `
CREATE TEMP TABLE importcerturls_temp (
	CA_ID integer,
	FIRST_CERTIFICATE_ID bigint,
	URL text,
	URL_TYPE integer
) ON COMMIT DROP
`); err != nil {
		goto done
	}
	// Prepare the list of URLs to copy.
	for url, cur := range cdpURLs {
		certURLsToImport = append(certURLsToImport, []any{cur.issuerCAID, cur.firstCertificateID, url, 0})
	}
	for url, cur := range ocspURLs {
		certURLsToImport = append(certURLsToImport, []any{cur.issuerCAID, cur.firstCertificateID, url, 1})
	}
	for url, cur := range caiURLs {
		certURLsToImport = append(certURLsToImport, []any{cur.issuerCAID, cur.firstCertificateID, url, 2})
	}
	// Copy the certificate URLs to the temporary table.
	if _, err = tx.CopyFrom(context.Background(), pgx.Identifier{"importcerturls_temp"}, []string{"ca_id", "first_certificate_id", "url", "url_type"}, pgx.CopyFromRows(certURLsToImport)); err != nil {
		goto done
	}
	// Process the list of certificate URLs.
	if _, err = tx.Exec(context.Background(), "SELECT process_cert_urls()"); err != nil {
		goto done
	}

	// Obtain further details of the "ca" rows that will need to be updated.
	for caID := range caMap {
		caIDs = append(caIDs, caID)
	}
	if rows, err = tx.Query(context.Background(), `
SELECT ca.ID, ca.LAST_NOT_AFTER, ca.NEXT_NOT_AFTER
	FROM ca
	WHERE ca.ID = ANY($1)
	FOR NO KEY UPDATE
`, caIDs); err != nil {
		goto done
	}
	defer rows.Close()
	for rows.Next() {
		var cur caUpdateRecord
		if err = rows.Scan(&cur.caID, &cur.lastNotAfter, &cur.nextNotAfter); err != nil {
			goto done
		}
		// Update the map of "ca" records that will need to be updated.
		cm := caMap[cur.caID]
		cm.lastNotAfter = cur.lastNotAfter
		cm.nextNotAfter = cur.nextNotAfter
		caMap[cur.caID] = cm
	}

	// Process the certs in this batch, to determine the required "ca" record updates.
	for _, c := range certs {
		cm := caMap[c.issuerCAID]
		if c.certID > cm.lastCertificateID {
			cm.lastCertificateID = c.certID
		}
		// Increment the issuance counter.
		switch c.numIndex {
		case 1:
			cm.numIssuedC++
		case 2:
			cm.numIssuedP++
		default:
			err = errors.New("unexpected numIndex")
			goto done
		}
		// If applicable, increment the expiration counter.
		if !c.notAfter.After(cm.lastNotAfter.Time) {
			switch c.numIndex {
			case 1:
				cm.numExpiredC++
			case 2:
				cm.numExpiredP++
			}
		} else if !cm.nextNotAfter.Valid || cm.nextNotAfter.Time.After(c.notAfter) {
			// If applicable, update the "next notAfter" timestamp.
			cm.nextNotAfter.Time = c.notAfter
			cm.nextNotAfter.Valid = true
		}
		// Update the map entry.
		caMap[c.issuerCAID] = cm
	}

	// Create a temporary table to assist with updating "ca" records.
	if _, err = tx.Exec(context.Background(), `
CREATE TEMP TABLE updatecarecords_temp (
	CA_ID integer,
	NUM_ISSUED_C integer,
	NUM_ISSUED_P integer,
	NUM_EXPIRED_C integer,
	NUM_EXPIRED_P integer,
	NEXT_NOT_AFTER timestamp,
	LAST_CERTIFICATE_ID bigint
) ON COMMIT DROP
`); err != nil {
		goto done
	}
	// Copy "ca" update details from caMap to a slice that's suitable to be copied to the temporary table.
	for _, cr := range caMap {
		caUpdates = append(caUpdates, []any{cr.caID, cr.numIssuedC, cr.numIssuedP, cr.numExpiredC, cr.numExpiredP, cr.nextNotAfter, cr.lastCertificateID})
	}
	// Copy the rows to the temporary table.
	if _, err = tx.CopyFrom(context.Background(), pgx.Identifier{"updatecarecords_temp"}, []string{"ca_id", "num_issued_c", "num_issued_p", "num_expired_c", "num_expired_p", "next_not_after", "last_certificate_id"}, pgx.CopyFromRows(caUpdates)); err != nil {
		goto done
	}
	// Update the "ca" rows.
	if _, err = tx.Exec(context.Background(), `
UPDATE ca
	SET NUM_ISSUED[1] = coalesce(ca.NUM_ISSUED[1], 0) + ucrt.NUM_ISSUED_C,
		NUM_ISSUED[2] = coalesce(ca.NUM_ISSUED[2], 0) + ucrt.NUM_ISSUED_P,
		NUM_EXPIRED[1] = coalesce(ca.NUM_EXPIRED[1], 0) + ucrt.NUM_EXPIRED_C,
		NUM_EXPIRED[2] = coalesce(ca.NUM_EXPIRED[2], 0) + ucrt.NUM_EXPIRED_P,
		NEXT_NOT_AFTER = ucrt.NEXT_NOT_AFTER,
		LAST_CERTIFICATE_ID = ucrt.LAST_CERTIFICATE_ID
	FROM updatecarecords_temp ucrt
	WHERE ca.ID = ucrt.CA_ID
`); err != nil {
		goto done
	}

	// Commit the transaction.
	if err = tx.Commit(context.Background()); err != nil {
		goto done
	}

done:
	if err != nil {
		LogPostgresError(err)
		return config.Config.Processor.RetryAfterErrorFrequency
	}

	logger.Logger.Info(
		"Certificates Processed",
		zap.Int64("count", numCerts),
		zap.Int64("start", startCertificateID),
		zap.Int64("end", endCertificateID),
		zap.Int64("latest", latestCertificateID),
		zap.Int64("behind", (latestCertificateID-endCertificateID)),
	)

	// Process next batch immediately.
	return 0
}

func numIndex(cert *x509.Certificate) int {
	for _, ext := range cert.Extensions {
		if x509.OIDExtensionCTPoison.Equal(ext.Id) && ext.Critical {
			return 2 // Precertificate.
		}
	}

	return 1 // Certificate.
}
