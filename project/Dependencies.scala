import sbt._

object Dependencies {

  object V {
    val pekko     = "1.1.1"
    val pekkoHttp = "1.1.0"
    val circe     = "0.14.9"
    val cats      = "3.5.4"
    val doobie    = "1.0.0-RC5"
    val aws       = "2.28.10"
    val jjwt      = "0.12.6"
    val logback   = "1.5.8"
    val slf4j     = "2.0.16"
    val scalatest = "3.2.19"
  }

  val core: Seq[ModuleID] = Seq(
    "org.typelevel" %% "cats-effect"   % V.cats,
    "io.circe"      %% "circe-core"    % V.circe,
    "io.circe"      %% "circe-generic" % V.circe,
    "io.circe"      %% "circe-parser"  % V.circe,
    "org.slf4j"      % "slf4j-api"     % V.slf4j
  )

  val pekkoHttp: Seq[ModuleID] = Seq(
    "org.apache.pekko" %% "pekko-actor-typed" % V.pekko,
    "org.apache.pekko" %% "pekko-stream"      % V.pekko,
    "org.apache.pekko" %% "pekko-http"        % V.pekkoHttp,
    "org.apache.pekko" %% "pekko-slf4j"       % V.pekko
  )

  val persistence: Seq[ModuleID] = Seq(
    "org.tpolecat" %% "doobie-core"       % V.doobie,
    "org.tpolecat" %% "doobie-postgres"   % V.doobie,
    "com.mysql"     % "mysql-connector-j" % "8.4.0"
  )

  val crypto: Seq[ModuleID] = Seq(
    "software.amazon.awssdk" % "kms"          % V.aws,
    "io.jsonwebtoken"        % "jjwt-api"     % V.jjwt,
    "io.jsonwebtoken"        % "jjwt-impl"    % V.jjwt % Runtime,
    "io.jsonwebtoken"        % "jjwt-jackson" % V.jjwt % Runtime
  )

  val logging: Seq[ModuleID] = Seq(
    "ch.qos.logback" % "logback-classic" % V.logback
  )

  val testing: Seq[ModuleID] = Seq(
    "org.scalatest"    %% "scalatest"                 % V.scalatest % Test,
    "org.apache.pekko" %% "pekko-actor-testkit-typed" % V.pekko     % Test,
    "org.apache.pekko" %% "pekko-http-testkit"        % V.pekkoHttp % Test
  )
}
