{-# LANGUAGE FlexibleContexts #-}

{-| Provides a general functionality for workers that run on the background
and perform some task when triggered.

Each task can process multiple triggers, if they're coming faster than the
tasks are being processed.

Properties:

- If a worked is triggered, it will perform its action eventually.
  (i.e. it won't miss a trigger).

- If the worker is busy, the new action will start immediately when it finishes
  the current one.

- If the worker is idle, it'll start the action immediately.

- If the caller uses 'triggerAndWait', the call will return just after the
  earliest action following the trigger is finished.

- If the worker finishes an action and there are no pending triggers since the
  start of the last action, it becomes idle and waits for a new trigger.

-}

{-

Copyright (C) 2014 Google Inc.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.

-}

module Ganeti.Utils.AsyncWorker
  ( AsyncWorker
  , mkAsyncWorker
  , trigger
  , triggerAndWait
  , triggerAndWaitMany
  ) where

import Control.Monad
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent (ThreadId)
import Control.Concurrent.Lifted (fork)
import Control.Concurrent.MVar.Lifted
import Data.Functor.Identity
import qualified Data.Traversable as T
import Data.IORef.Lifted

-- Represents the state of the requests to the worker. The worker is either
-- 'Idle', or has 'Pending' triggers to process. After the corresponding
-- action is run, all the 'MVar's in the list are notified with the result.
-- Note that the action needs to be run even if the list is empty, as it
-- means that there are pending requests, only nobody needs to be notified of
-- their results.
data TriggerState a
  = Idle
  | Pending [MVar a]


-- | Adds a new trigger to the current state (therefore the result is always
-- 'Pending'), optionally adding a 'MVar' that will receive the output.
addTrigger :: Maybe (MVar a) -> TriggerState a -> TriggerState a
addTrigger mmvar state = let rs = recipients state
                         in Pending $ maybe rs (: rs) mmvar
  where
    recipients Idle         = []
    recipients (Pending rs) = rs

-- | Represent an asynchronous worker whose single action execution returns a
-- value of type @a@.
data AsyncWorker a
    = AsyncWorker ThreadId (IORef (TriggerState a)) (MVar ())

-- | Given an action, construct an 'AsyncWorker'.
mkAsyncWorker :: (MonadBaseControl IO m) => m a -> m (AsyncWorker a)
mkAsyncWorker act = do
    trig <- newMVar ()
    ref <- newIORef Idle
    thId <- fork . forever $ do
        takeMVar trig           -- wait for a trigger
        state <- swap ref Idle  -- check the state of pending requests
        -- if there are pending requests, run the action and send them results
        case state of
          Idle        -> return () -- all trigers have been processed, we've
                                   -- been woken up by a trigger that has been
                                   -- already included in the last run
          Pending rs  -> act >>= forM_ rs . flip tryPutMVar
    return $ AsyncWorker thId ref trig
  where
    swap :: (MonadBase IO m) => IORef a -> a -> m a
    swap ref x = atomicModifyIORef ref ((,) x)

-- An internal function for triggering a worker, optionally registering
-- a callback 'MVar'
triggerInternal :: (MonadBase IO m)
                => Maybe (MVar a) -> AsyncWorker a -> m ()
triggerInternal mmvar (AsyncWorker _ ref trig) = do
    atomicModifyIORef ref (\ts -> (addTrigger mmvar ts, ()))
    _ <- tryPutMVar trig ()
    return ()

-- | Trigger a worker, letting it run its action asynchronously, but do not
-- wait for the result.
trigger :: (MonadBase IO m) => AsyncWorker a -> m ()
trigger = triggerInternal Nothing

-- | Trigger a list of workers and wait until all the actions following these
-- triggers finish. Returns the results of the actions.
--
-- Note that there is a significant difference between 'triggerAndWaitMany'
-- and @mapM triggerAndWait@. The latter runs all the actions of the workers
-- sequentially, while the former runs them in parallel.
triggerAndWaitMany :: (T.Traversable t, MonadBase IO m)
                   => t (AsyncWorker a) -> m (t a)
triggerAndWaitMany workers =
    let trig w = do
                  result <- newEmptyMVar
                  triggerInternal (Just result) w
                  return result
    in T.mapM trig workers >>= T.mapM takeMVar

-- | Trigger a worker and wait until the action following this trigger
-- finishes. Return the result of the action.
triggerAndWait :: (MonadBase IO m) => AsyncWorker a -> m a
triggerAndWait = liftM runIdentity . triggerAndWaitMany . Identity
