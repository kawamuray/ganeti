{-| Implementation of Ganeti Lock field queries

The actual computation of the field values is done by forwarding
the request; so only have a minimal field definition here.

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

module Ganeti.Query.Locks
  ( fieldsMap
  , RuntimeData
  ) where

import qualified Text.JSON as J

import Ganeti.Locking.Allocation (OwnerState(..))
import Ganeti.Locking.Locks (GanetiLocks, ClientId, ciIdentifier)
import Ganeti.Query.Common
import Ganeti.Query.Language
import Ganeti.Query.Types

-- | The runtime information for locks. As all information about locks
-- is handled by WConfD, the actual information is obtained as live data.
-- The type represents the information for a single lock, even though all
-- locks are queried simultaneously, ahead of time.
type RuntimeData = Maybe (GanetiLocks, [(ClientId, OwnerState)])

-- | Obtain the owners of a lock from the runtime data.
getOwners :: RuntimeData -> a -> ResultEntry
getOwners (Just (_, ownerinfo)) _ =
  rsNormal . map (J.encode . ciIdentifier . fst)
    $ ownerinfo
getOwners _ _ = rsNormal ([] :: [(ClientId, OwnerState)])

-- | Obtain the mode of a lock from the runtime data.
getMode :: RuntimeData -> a -> ResultEntry
getMode (Just (_, ownerinfo)) _
  | null ownerinfo = rsNormal J.JSNull
  | any ((==) OwnExclusive . snd) ownerinfo = rsNormal "exclusive"
  | otherwise = rsNormal "shared"
getMode _ _ = rsNormal J.JSNull

-- | List of all lock fields.
lockFields :: FieldList String RuntimeData
lockFields =
  [ (FieldDefinition "name" "Name" QFTOther "Lock name",
     FieldSimple rsNormal, QffNormal)
  , (FieldDefinition "mode" "Mode" QFTOther "Mode in which the lock is\
                                             \ currently acquired\
                                             \ (exclusive or shared)",
     FieldRuntime getMode, QffNormal)
  , (FieldDefinition "owner" "Owner" QFTOther "Current lock owner(s)",
     FieldRuntime getOwners, QffNormal)
  , (FieldDefinition "pending" "Pending" QFTOther "Jobs waiting for the lock",
     FieldSimple (const $ rsNormal ([] :: [ClientId])), QffNormal)
    -- TODO: as soon as jobs stop polling, report the pending locks
  ]

-- | The lock fields map.
fieldsMap :: FieldMap String RuntimeData
fieldsMap = fieldListToFieldMap lockFields
