{-| Implementation of the Ganeti Query2 node group queries.

 -}

{-

Copyright (C) 2012 Google Inc.

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

module Ganeti.Query.Network
  ( NetworkRuntime(..)
  , networkFieldsMap
  ) where

import qualified Data.Map as Map

import Ganeti.Config
import Ganeti.Objects
import Ganeti.Query.Language
import Ganeti.Query.Common
import Ganeti.Query.Types

data NetworkRuntime = NetworkRuntime

networkFields :: FieldList Network NetworkRuntime
networkFields =
  [ (FieldDefinition "name" "Name" QFTText "Network name",
     FieldSimple (rsNormal . networkName), QffNormal)
  , (FieldDefinition "network" "Subnet" QFTText "IPv4 subnet",
     FieldSimple (rsNormal . networkNetwork), QffNormal)
  , (FieldDefinition "gateway" "Gateway" QFTOther "IPv4 gateway",
     FieldSimple (rsMaybeUnavail . networkGateway), QffNormal)
  , (FieldDefinition "network6" "IPv6Subnet" QFTOther "IPv6 subnet",
     FieldSimple (rsMaybeUnavail . networkNetwork6), QffNormal)
  , (FieldDefinition "gateway6" "IPv6Gateway" QFTOther "IPv6 gateway",
     FieldSimple (rsMaybeUnavail . networkGateway6), QffNormal)
  , (FieldDefinition "mac_prefix" "MacPrefix" QFTOther "MAC address prefix",
     FieldSimple (rsMaybeUnavail . networkMacPrefix), QffNormal)
  , (FieldDefinition "network_type" "NetworkType" QFTOther "Network type",
     FieldSimple (rsMaybeUnavail . networkNetworkType), QffNormal)
  , (FieldDefinition "group_list" "GroupList" QFTOther "List of node groups",
     FieldConfig (\cfg -> rsNormal . getGroupConnections cfg . networkUuid),
       QffNormal)
  ] ++
  uuidFields "Network" ++
  serialFields "Network" ++
  tagsFields

-- | The group fields map.
networkFieldsMap :: FieldMap Network NetworkRuntime
networkFieldsMap =
  Map.fromList $ map (\v@(f, _, _) -> (fdefName f, v)) networkFields

-- TODO: the following fields are not implemented yet: external_reservations,
-- free_count, group_cnt, inst_cnt, inst_list, map, reserved_count, serial_no,
-- tags, uuid