/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "shutdown.h"

using namespace tachyon::shutdown;

class ShutdownTest : public ::testing::Test {
  protected:
    void SetUp() override {
        g_exiting = 0;
        g_draining = 0;
        g_reload_config = 0;
        g_hot_restart = 0;
    }
};

TEST_F(ShutdownTest, InitialFlagsAreZero) {
    EXPECT_EQ(g_exiting, 0);
    EXPECT_EQ(g_draining, 0);
    EXPECT_EQ(g_reload_config, 0);
    EXPECT_EQ(g_hot_restart, 0);
}

TEST_F(ShutdownTest, EnterDrainSetsState) {
    DrainState s;
    enter_drain(s, 10, 1000);
    EXPECT_TRUE(s.active);
    EXPECT_EQ(s.entered_ts, 1000u);
    EXPECT_EQ(s.budget_sec, 10u);
}

TEST_F(ShutdownTest, EnterDrainIsIdempotent) {
    DrainState s;
    enter_drain(s, 10, 1000);
    enter_drain(s, 99, 9999); /* second call ignored */
    EXPECT_EQ(s.entered_ts, 1000u);
    EXPECT_EQ(s.budget_sec, 10u);
}

TEST_F(ShutdownTest, DrainNotExpiredWithinBudget) {
    DrainState s;
    enter_drain(s, 10, 1000);
    EXPECT_FALSE(drain_expired(s, 1005));
    EXPECT_FALSE(drain_expired(s, 1009));
}

TEST_F(ShutdownTest, DrainExpiredAtBudget) {
    DrainState s;
    enter_drain(s, 10, 1000);
    EXPECT_TRUE(drain_expired(s, 1010));
    EXPECT_TRUE(drain_expired(s, 1100));
}

TEST_F(ShutdownTest, DrainExpiredWhenInactive) {
    DrainState s;
    /* Never entered drain → vacuously expired */
    EXPECT_TRUE(drain_expired(s, 5000));
}

TEST_F(ShutdownTest, ShouldNotExitWhenNotExiting) {
    DrainState s;
    EXPECT_FALSE(should_exit(s, 0));
}

TEST_F(ShutdownTest, ShouldExitImmediatelyIfDrainNotActive) {
    DrainState s;
    g_exiting = 1;
    EXPECT_TRUE(should_exit(s, 0));
}

TEST_F(ShutdownTest, ShouldNotExitDuringDrain) {
    DrainState s;
    g_exiting = 1;
    enter_drain(s, 10, 1000);
    EXPECT_FALSE(should_exit(s, 1005));
}

TEST_F(ShutdownTest, ShouldExitAfterDrainBudget) {
    DrainState s;
    g_exiting = 1;
    enter_drain(s, 10, 1000);
    EXPECT_TRUE(should_exit(s, 1010));
}

TEST_F(ShutdownTest, DrainSecondsConfigurable) {
    g_drain_seconds.store(20);
    EXPECT_EQ(g_drain_seconds.load(), 20u);
    g_drain_seconds.store(5);
    EXPECT_EQ(g_drain_seconds.load(), 5u);
}

TEST_F(ShutdownTest, InstallHandlersDoesNotCrash) {
    install_handlers();
    install_handlers(); /* idempotent */
    EXPECT_EQ(g_exiting, 0);
}
