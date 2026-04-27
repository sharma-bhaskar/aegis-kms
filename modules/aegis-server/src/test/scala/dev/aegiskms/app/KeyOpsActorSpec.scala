package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.*
import dev.aegiskms.persistence.EventJournal
import org.apache.pekko.actor.testkit.typed.scaladsl.ScalaTestWithActorTestKit
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpecLike

/** Tests the core lifecycle behavior of `KeyOpsActor` using Pekko's typed `ActorTestKit`.
  *
  * Every test gets a fresh `EventJournal[IO]` and a fresh actor, so tests are independent.
  */
final class KeyOpsActorSpec extends ScalaTestWithActorTestKit with AnyWordSpecLike with Matchers:

  private given IORuntime      = IORuntime.global
  private val alice: Principal = Principal.Human("alice", Set("admins"))

  private def freshActor() =
    val journal = EventJournal.inMemory.unsafeRunSync()
    val behavior =
      KeyOpsActor.behavior(journal, replayed = Nil)
    (journal, spawn(behavior))

  "KeyOpsActor" should {

    "create a key in PreActive state and append a Created event" in {
      val (journal, actor) = freshActor()
      val probe            = createTestProbe[Either[KmsError, ManagedKey]]()

      actor ! KeyOpsActor.Create(KeySpec.aes256("invoice-signing"), alice, probe.ref)

      val res = probe.receiveMessage()
      res.isRight shouldBe true
      val created = res.toOption.get
      created.spec.name shouldBe "invoice-signing"
      created.state shouldBe KeyState.PreActive

      val events = journal.replay().unsafeRunSync()
      events.size shouldBe 1
      events.head shouldBe a[KeyEvent.Created]
      events.head.keyId shouldBe created.id
    }

    "transition PreActive -> Active on Activate and append an Activated event" in {
      val (journal, actor) = freshActor()
      val createProbe      = createTestProbe[Either[KmsError, ManagedKey]]()
      val activateProbe    = createTestProbe[Either[KmsError, ManagedKey]]()

      actor ! KeyOpsActor.Create(KeySpec.aes256("rotate-me"), alice, createProbe.ref)
      val id = createProbe.receiveMessage().toOption.get.id

      actor ! KeyOpsActor.Activate(id, alice, activateProbe.ref)
      val activated = activateProbe.receiveMessage()
      activated.isRight shouldBe true
      activated.toOption.get.state shouldBe KeyState.Active

      val events = journal.replay().unsafeRunSync()
      events.size shouldBe 2
      events.last shouldBe a[KeyEvent.Activated]
    }

    "return ItemNotFound for an unknown key" in {
      val (_, actor) = freshActor()
      val probe      = createTestProbe[Either[KmsError, ManagedKey]]()

      actor ! KeyOpsActor.Get(KeyId.generate(), alice, probe.ref)
      val res = probe.receiveMessage()
      res.isLeft shouldBe true
      res.swap.toOption.get.code shouldBe ErrorCode.ItemNotFound
    }

    "destroy removes the key and appends a Destroyed event" in {
      val (journal, actor) = freshActor()
      val createProbe      = createTestProbe[Either[KmsError, ManagedKey]]()
      val destroyProbe     = createTestProbe[Either[KmsError, Unit]]()
      val getProbe         = createTestProbe[Either[KmsError, ManagedKey]]()

      actor ! KeyOpsActor.Create(KeySpec.aes256("ephemeral"), alice, createProbe.ref)
      val id = createProbe.receiveMessage().toOption.get.id

      actor ! KeyOpsActor.Destroy(id, alice, destroyProbe.ref)
      destroyProbe.receiveMessage().isRight shouldBe true

      actor ! KeyOpsActor.Get(id, alice, getProbe.ref)
      val gone = getProbe.receiveMessage()
      gone.isLeft shouldBe true
      gone.swap.toOption.get.code shouldBe ErrorCode.ItemNotFound

      val events = journal.replay().unsafeRunSync()
      events.last shouldBe a[KeyEvent.Destroyed]
    }

    "replay rebuilds state deterministically from a journal" in {
      // Arrange: one journal, drive the actor through Create + Activate.
      val journal     = EventJournal.inMemory.unsafeRunSync()
      val actor1      = spawn(KeyOpsActor.behavior(journal, replayed = Nil))
      val createProbe = createTestProbe[Either[KmsError, ManagedKey]]()
      val activate    = createTestProbe[Either[KmsError, ManagedKey]]()

      actor1 ! KeyOpsActor.Create(KeySpec.aes256("survives-restart"), alice, createProbe.ref)
      val id = createProbe.receiveMessage().toOption.get.id
      actor1 ! KeyOpsActor.Activate(id, alice, activate.ref)
      activate.receiveMessage().isRight shouldBe true

      // Act: spin up a fresh actor that replays the same journal.
      val replayed = journal.replay().unsafeRunSync()
      val actor2   = spawn(KeyOpsActor.behavior(journal, replayed))
      val getProbe = createTestProbe[Either[KmsError, ManagedKey]]()
      actor2 ! KeyOpsActor.Get(id, alice, getProbe.ref)

      // Assert: the new actor sees the same key in the same state.
      val after = getProbe.receiveMessage()
      after.isRight shouldBe true
      after.toOption.get.state shouldBe KeyState.Active
      after.toOption.get.spec.name shouldBe "survives-restart"
    }
  }
