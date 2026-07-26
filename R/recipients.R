# Recipients are always plain "age1..." character strings in this package;
# there is no recipient class. Validation of the bech32 encoding happens in C
# when the strings are consumed by the encrypt entry points.

as_recipients <- function(recipients) {
  if (inherits(recipients, "age_identity")) {
    age_abort(
      "recipient",
      paste(
        "`recipients` must be \"age1...\" strings, not an identity;",
        "call age_pubkey() to derive them"
      )
    )
  }
  if (!is.character(recipients) || length(recipients) == 0L) {
    age_abort("recipient", "`recipients` must be a non-empty character vector")
  }
  if (anyNA(recipients)) {
    age_abort("recipient", "`recipients` must not contain NA")
  }
  recipients
}
