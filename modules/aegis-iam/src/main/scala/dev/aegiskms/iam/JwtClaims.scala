package dev.aegiskms.iam

import java.time.Instant

/** Typed view of the claims encoded in an Aegis-issued JWS.
  *
  * The wire format is plain JWT (`iat`/`exp`/`iss`/`sub` from RFC 7519 plus Aegis-namespaced custom claims
  * prefixed `aegis_`). This sealed ADT discriminates Human vs Agent at the type level so downstream code
  * cannot accidentally treat one as the other.
  *
  * Claim layout on the wire:
  * {{{
  *   {
  *     "sub":   "alice@org",            // RFC 7519
  *     "iss":   "https://aegis.local",  // RFC 7519, optional
  *     "iat":   1714400000,             // RFC 7519, seconds since epoch
  *     "exp":   1714403600,             // RFC 7519, seconds since epoch
  *     "aegis_kind":     "human",       // "human" | "agent"
  *     "aegis_groups":   ["admins"],    // human only
  *     "aegis_parent":   "alice@org",   // agent only — subject of the parent human
  *     "aegis_purpose":  "claude-...",  // agent only
  *     "aegis_ops":      ["Sign","Get"] // agent only — Operation enum names
  *   }
  * }}}
  *
  * The `aegis_*` namespace is reserved so we don't trample on standard OIDC claims (`groups`, `roles`,
  * `scope`) when Aegis is fronted by a corporate IDP.
  */
sealed trait JwtClaims:
  def subject: String
  def issuer: Option[String]
  def issuedAt: Instant
  def expiresAt: Instant

object JwtClaims:

  final case class Human(
      subject: String,
      issuer: Option[String],
      issuedAt: Instant,
      expiresAt: Instant,
      groups: Set[String]
  ) extends JwtClaims

  final case class Agent(
      subject: String,
      issuer: Option[String],
      issuedAt: Instant,
      expiresAt: Instant,
      parentSubject: String,
      purpose: String,
      allowedOps: Set[String]
  ) extends JwtClaims

  /** Custom-claim names. Constants so the verifier and the issuer stay in lockstep. */
  object Claim:
    val Kind          = "aegis_kind"
    val Groups        = "aegis_groups"
    val ParentSubject = "aegis_parent"
    val Purpose       = "aegis_purpose"
    val AllowedOps    = "aegis_ops"

    val KindHuman = "human"
    val KindAgent = "agent"
