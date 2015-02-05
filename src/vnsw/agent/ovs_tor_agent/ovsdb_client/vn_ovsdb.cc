/*
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

extern "C" {
#include <ovsdb_wrapper.h>
};
#include <vn_ovsdb.h>

#include <oper/vn.h>
#include <ovsdb_types.h>

using OVSDB::OvsdbDBEntry;
using OVSDB::VnOvsdbEntry;
using OVSDB::VnOvsdbObject;

VnOvsdbEntry::VnOvsdbEntry(VnOvsdbObject *table,
        const boost::uuids::uuid &uuid) : OvsdbDBEntry(table), uuid_(uuid) {
}

void VnOvsdbEntry::AddMsg(struct ovsdb_idl_txn *txn) {
}

void VnOvsdbEntry::ChangeMsg(struct ovsdb_idl_txn *txn) {
}

void VnOvsdbEntry::DeleteMsg(struct ovsdb_idl_txn *txn) {
}

bool VnOvsdbEntry::Sync(DBEntry *db_entry) {
    return false;
}

bool VnOvsdbEntry::IsLess(const KSyncEntry &entry) const {
    const VnOvsdbEntry &vn_entry = static_cast<const VnOvsdbEntry&>(entry);
    return uuid_ < vn_entry.uuid_;
}

KSyncEntry *VnOvsdbEntry::UnresolvedReference() {
    return NULL;
}

VnOvsdbObject::VnOvsdbObject(OvsdbClientIdl *idl, DBTable *table) :
    OvsdbDBObject(idl, table) {
}

VnOvsdbObject::~VnOvsdbObject() {
}

void VnOvsdbObject::OvsdbNotify(OvsdbClientIdl::Op op,
        struct ovsdb_idl_row *row) {
}

KSyncEntry *VnOvsdbObject::Alloc(const KSyncEntry *key, uint32_t index) {
    const VnOvsdbEntry *k_entry =
        static_cast<const VnOvsdbEntry *>(key);
    VnOvsdbEntry *entry = new VnOvsdbEntry(this, k_entry->uuid_);
    return entry;
}

KSyncEntry *VnOvsdbObject::DBToKSyncEntry(const DBEntry* db_entry) {
    const VnEntry *entry = static_cast<const VnEntry *>(db_entry);
    VnOvsdbEntry *key = new VnOvsdbEntry(this, entry->GetUuid());
    return static_cast<KSyncEntry *>(key);
}

OvsdbDBEntry *VnOvsdbObject::AllocOvsEntry(struct ovsdb_idl_row *row) {
    return NULL;
}

KSyncDBObject::DBFilterResp VnOvsdbObject::DBEntryFilter(
        const DBEntry *entry) {
    const VnEntry *vn = static_cast<const VnEntry *>(entry);
    // only accept Virtual Networks with non-NULL vrf.
    if (vn->GetVrf() == NULL) {
        return DBFilterDelete;
    }
    return DBFilterAccept;
}
