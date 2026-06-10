#!/bin/sh
# =============================================================================
#  tls-checker.sh
#  Εργαλείο αυτοματοποιημένου ελέγχου TLS με χρήση openssl s_client
#  Cyber Security - 3η Εργασία (Ερώτημα 3)
#
#  Έλεγχοι:
#   (1) Έκδοση πρωτοκόλλου  -> επιτρέπονται ΜΟΝΟ TLS 1.2 και TLS 1.3
#   (2) Λίστα αδύναμων ciphers (RC4, DES, 3DES, NULL, EXPORT, MD5, SHA1)
#   (3) Έλεγχος πιστοποιητικού: εγκυρότητα, ημερομηνίες ΚΑΙ domain name
#
#  Χρήση: ./tls-checker.sh <hostname> [port]
# =============================================================================

HOST=$1
PORT=${2:-443}

if [ -z "$HOST" ]; then
    echo "Χρήση: $0 <hostname> [port]"
    exit 1
fi

echo "=========================================="
echo " Ξεκινάει ο έλεγχος για: $HOST:$PORT"
echo "=========================================="

# -----------------------------------------------------------------------------
# (1) ΕΛΕΓΧΟΣ ΕΚΔΟΣΗΣ ΠΡΩΤΟΚΟΛΛΟΥ
#     Στόχος: Καμία έκδοση εκτός από TLS 1.2 και TLS 1.3 δεν επιτρέπεται.
# -----------------------------------------------------------------------------
echo ""
echo "[*] 1. ΕΛΕΓΧΟΣ ΕΚΔΟΣΗΣ ΠΡΩΤΟΚΟΛΛΟΥ SSL/TLS"

# 1α. Τα παρωχημένα πρωτόκολλα ΠΡΕΠΕΙ να απορρίπτονται
echo "  --- Παρωχημένα πρωτόκολλα (πρέπει να ΑΠΟΡΡΙΠΤΟΝΤΑΙ) ---"
for protocol in "-ssl3" "-tls1" "-tls1_1"; do
    if echo "Q" | openssl s_client -connect "$HOST:$PORT" $protocol -no_ign_eof 2>&1 | grep -q "CONNECTED"; then
        echo "  [!] ΚΙΝΔΥΝΟΣ: Ο server επιτρέπει το αδύναμο πρωτόκολλο $protocol"
    else
        echo "  [+] Ασφαλές: Το $protocol απορρίφθηκε."
    fi
done

# 1β. Τα σύγχρονα πρωτόκολλα ΠΡΕΠΕΙ να υποστηρίζονται
echo "  --- Σύγχρονα πρωτόκολλα (πρέπει να ΕΠΙΤΡΕΠΟΝΤΑΙ) ---"
for protocol in "-tls1_2" "-tls1_3"; do
    if echo "Q" | openssl s_client -connect "$HOST:$PORT" $protocol -no_ign_eof 2>&1 | grep -q "CONNECTED"; then
        echo "  [+] OK: Ο server υποστηρίζει το $protocol (επιτρεπόμενο)."
    else
        echo "  [!] ΠΡΟΣΟΧΗ: Το $protocol δεν είναι διαθέσιμο σε αυτόν τον server."
    fi
done

# -----------------------------------------------------------------------------
# (2) ΕΛΕΓΧΟΣ ΑΔΥΝΑΜΩΝ CIPHERS
#     Λίστα αδύναμων αλγορίθμων. Με @SECLEVEL=0 παρακάμπτουμε τον τοπικό
#     περιορισμό του OpenSSL 3.x ώστε να ελέγξουμε τι προσφέρει ο server.
# -----------------------------------------------------------------------------
echo ""
echo "[*] 2. ΕΛΕΓΧΟΣ ΑΔΥΝΑΜΩΝ ΚΡΥΠΤΟΓΡΑΦΙΚΩΝ ΑΛΓΟΡΙΘΜΩΝ"

# Λίστα αδύναμων / παρωχημένων αλγορίθμων προς έλεγχο.
# Σημ.: Αν κάποιος δεν υποστηρίζεται καθόλου τοπικά, ο έλεγχος SHA δουλεύει σίγουρα.
WEAK_CIPHERS="RC4 DES 3DES NULL EXP MD5 SHA"

for cipher in $WEAK_CIPHERS; do
    OUT=$(echo "Q" | openssl s_client -connect "$HOST:$PORT" -cipher "$cipher@SECLEVEL=0" -no_ign_eof 2>&1)
    # Αν δεν αναγνωρίζεται καν ο cipher τοπικά -> δεν μπορούμε να τον δοκιμάσουμε
    if echo "$OUT" | grep -q -i "no cipher match\|no ciphers available"; then
        echo "  [-] Ο cipher $cipher δεν υποστηρίζεται τοπικά (παράλειψη ελέγχου)."
        continue
    fi
    # Αν η χειραψία πέτυχε με αυτόν τον αδύναμο cipher -> ΚΙΝΔΥΝΟΣ
    if echo "$OUT" | grep -E -q "Cipher.*($cipher)"; then
        echo "  [!] ΚΙΝΔΥΝΟΣ: Υποστηρίζεται ο αδύναμος cipher: $cipher"
    else
        echo "  [+] Ασφαλές: Ο cipher $cipher απορρίφθηκε."
    fi
done

# -----------------------------------------------------------------------------
# (3) ΕΛΕΓΧΟΣ ΠΙΣΤΟΠΟΙΗΤΙΚΟΥ
#     - Εγκυρότητα αλυσίδας (verify return code)
#     - Ημερομηνίες ισχύος (notBefore / notAfter)
#     - Domain name (hostname verification)
# -----------------------------------------------------------------------------
echo ""
echo "[*] 3. ΕΛΕΓΧΟΣ ΕΓΚΥΡΟΤΗΤΑΣ ΠΙΣΤΟΠΟΙΗΤΙΚΟΥ"

# Αποθηκεύουμε το output σε προσωρινό αρχείο (αποφυγή απώλειας δεδομένων από piping).
# Το -verify_hostname ελέγχει αν το CN/SAN ταιριάζει με το ζητούμενο domain.
echo "Q" | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" \
    -verify_hostname "$HOST" -showcerts -cipher "ALL@SECLEVEL=0" > s_client_output.txt 2>&1

# 3α. Εγκυρότητα αλυσίδας
if grep -q "Verify return code: 0" s_client_output.txt; then
    echo "  [+] Το πιστοποιητικό είναι έγκυρο (Return Code: 0)."
else
    ERROR_CODE=$(grep "Verify return code" s_client_output.txt | head -n 1)
    echo "  [!] ΣΦΑΛΜΑ ΠΙΣΤΟΠΟΙΗΤΙΚΟΥ: $ERROR_CODE"
fi

# 3β. Έλεγχος Domain Name (hostname verification)
echo "  Έλεγχος Domain Name (Hostname):"
if grep -q -i "Hostname mismatch" s_client_output.txt; then
    echo "  [!] ΚΙΝΔΥΝΟΣ: Το domain name ($HOST) ΔΕΝ ταιριάζει με το πιστοποιητικό (Hostname mismatch)."
elif grep -q "Verify return code: 0" s_client_output.txt; then
    echo "  [+] OK: Το domain name ($HOST) ταιριάζει με το CN/SAN του πιστοποιητικού."
else
    echo "  [-] Ο έλεγχος hostname δεν ολοκληρώθηκε λόγω άλλου σφάλματος επαλήθευσης."
fi

# 3γ. Ημερομηνίες ισχύος
echo "  Ημερομηνίες Ισχύος:"
sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' s_client_output.txt > temp_cert.pem

if [ -s temp_cert.pem ]; then
    openssl x509 -in temp_cert.pem -noout -dates | while read -r line; do
        echo "  -> $line"
    done
    # Έλεγχος αν το πιστοποιητικό έχει λήξει
    if openssl x509 -in temp_cert.pem -noout -checkend 0 >/dev/null 2>&1; then
        echo "  [+] OK: Το πιστοποιητικό είναι εντός ισχύος (δεν έχει λήξει)."
    else
        echo "  [!] ΚΙΝΔΥΝΟΣ: Το πιστοποιητικό έχει ΛΗΞΕΙ."
    fi
else
    echo "  [!] Δεν βρέθηκε πιστοποιητικό για ανάγνωση."
fi

# Καθαρισμός προσωρινών αρχείων
rm -f s_client_output.txt temp_cert.pem

echo "=========================================="
