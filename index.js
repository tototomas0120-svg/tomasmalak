const { onCall, HttpsError } = require('firebase-functions/v2/https');

const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const {
    getFirestore,
    FieldValue
} = require('firebase-admin/firestore');

initializeApp();

const auth = getAuth();
const db = getFirestore();

const ALLOWED_ROLES = [
    "admin",
    "manager",
    "driver"
];

async function requireAdmin(request) {

    if (!request.auth) {
        throw new HttpsError(
            "unauthenticated",
            "يجب تسجيل الدخول."
        );
    }

    const snap = await db
        .collection("users")
        .doc(request.auth.uid)
        .get();

    const data = snap.exists
        ? snap.data()
        : null;

    if (
        !data ||
        String(data.role || "").toLowerCase() !== "admin" ||
        data.active === false
    ) {
        throw new HttpsError(
            "permission-denied",
            "ليس لديك صلاحية مسؤول النظام."
        );
    }

    return data;
}


/* ================================
   GET ALL USERS
================================ */

exports.getAllUsers = onCall(
    {
        cors: [
            "http://127.0.0.1:5500",
            "http://localhost:5500"
        ]
    },
    async (request) => {

        await requireAdmin(request);

        const snap = await db
            .collection("users")
            .get();

        return snap.docs.map(doc => ({
            uid: doc.id,
            ...doc.data()
        }));
    }
);


/* ================================
   CREATE USER
================================ */

exports.createUser = onCall(
    {
        cors: [
            "http://127.0.0.1:5500",
            "http://localhost:5500"
        ]
    },
    async (request) => {

        await requireAdmin(request);

        const {
            name,
            email,
            password,
            role
        } = request.data || {};

        const cleanName =
            String(name || "").trim();

        const cleanEmail =
            String(email || "")
                .trim()
                .toLowerCase();

        const cleanPassword =
            String(password || "");

        const cleanRole =
            String(role || "driver")
                .trim()
                .toLowerCase();

        if (
            !cleanName ||
            !cleanEmail ||
            !cleanPassword ||
            !ALLOWED_ROLES.includes(cleanRole)
        ) {
            throw new HttpsError(
                "invalid-argument",
                "بيانات المستخدم غير مكتملة."
            );
        }

        if (cleanPassword.length < 6) {
            throw new HttpsError(
                "invalid-argument",
                "كلمة المرور يجب أن تكون 6 أحرف على الأقل."
            );
        }

        try {

            const user = await auth.createUser({
                email: cleanEmail,
                password: cleanPassword,
                displayName: cleanName,
                disabled: false
            });

            await db
                .collection("users")
                .doc(user.uid)
                .set({
                    name: cleanName,
                    email: cleanEmail,
                    role: cleanRole,
                    active: true,
                    createdAt:
                        FieldValue.serverTimestamp()
                });

            return {
                ok: true,
                uid: user.uid
            };

        } catch (e) {

            if (
                e.code ===
                "auth/email-already-exists"
            ) {

                throw new HttpsError(
                    "already-exists",
                    "البريد الإلكتروني مستخدم بالفعل."
                );
            }

            throw new HttpsError(
                "internal",
                e.message ||
                "تعذر إنشاء المستخدم."
            );
        }
    }
);


/* ================================
   UPDATE USER
================================ */

exports.updateUser = onCall(
    {
        cors: [
            "http://127.0.0.1:5500",
            "http://localhost:5500"
        ]
    },
    async (request) => {

        await requireAdmin(request);

        const {
            uid,
            name,
            email,
            role,
            active
        } = request.data || {};

        if (!uid) {
            throw new HttpsError(
                "invalid-argument",
                "UID مطلوب."
            );
        }

        if (
            uid === request.auth.uid &&
            active === false
        ) {
            throw new HttpsError(
                "failed-precondition",
                "لا يمكنك تعطيل حسابك."
            );
        }

        if (
            uid === request.auth.uid &&
            role !== undefined &&
            String(role).toLowerCase() !== "admin"
        ) {
            throw new HttpsError(
                "failed-precondition",
                "لا يمكنك إزالة صلاحية المسؤول من حسابك."
            );
        }

        const authUpdate = {};

        if (email !== undefined) {
            authUpdate.email =
                String(email)
                    .trim()
                    .toLowerCase();
        }

        if (active !== undefined) {
            authUpdate.disabled =
                active === false;
        }

        if (name !== undefined) {
            authUpdate.displayName =
                String(name).trim();
        }

        try {

            if (
                Object.keys(authUpdate).length > 0
            ) {

                await auth.updateUser(
                    uid,
                    authUpdate
                );
            }

            const profile = {};

            if (name !== undefined) {
                profile.name =
                    String(name).trim();
            }

            if (email !== undefined) {
                profile.email =
                    String(email)
                        .trim()
                        .toLowerCase();
            }

            if (role !== undefined) {

                const cleanRole =
                    String(role)
                        .trim()
                        .toLowerCase();

                if (
                    !ALLOWED_ROLES.includes(cleanRole)
                ) {
                    throw new HttpsError(
                        "invalid-argument",
                        "الصلاحية غير صحيحة."
                    );
                }

                if (
                    uid === request.auth.uid &&
                    cleanRole !== "admin"
                ) {
                    throw new HttpsError(
                        "failed-precondition",
                        "لا يمكنك إزالة صلاحية المسؤول من حسابك."
                    );
                }

                profile.role = cleanRole;
            }

            if (active !== undefined) {
                profile.active =
                    Boolean(active);
            }

            if (
                Object.keys(profile).length > 0
            ) {

                await db
                    .collection("users")
                    .doc(uid)
                    .set(
                        profile,
                        {
                            merge: true
                        }
                    );
            }

            return {
                ok: true
            };

        } catch (e) {

            if (e instanceof HttpsError) {
                throw e;
            }

            if (
                e.code ===
                "auth/email-already-exists"
            ) {
                throw new HttpsError(
                    "already-exists",
                    "البريد الإلكتروني مستخدم بالفعل."
                );
            }

            if (
                e.code ===
                "auth/user-not-found"
            ) {
                throw new HttpsError(
                    "not-found",
                    "المستخدم غير موجود."
                );
            }

            throw new HttpsError(
                "internal",
                e.message ||
                "تعذر تعديل المستخدم."
            );
        }
    }
);


/* ================================
   CHANGE USER PASSWORD
================================ */

exports.changeUserPassword = onCall(
    {
        cors: [
            "http://127.0.0.1:5500",
            "http://localhost:5500"
        ]
    },
    async (request) => {

        await requireAdmin(request);

        const {
            uid,
            password
        } = request.data || {};

        if (
            !uid ||
            !password ||
            String(password).length < 6
        ) {
            throw new HttpsError(
                "invalid-argument",
                "UID وكلمة مرور صحيحة مطلوبان."
            );
        }

        if (uid === request.auth.uid) {
            throw new HttpsError(
                "failed-precondition",
                "استخدم تغيير كلمة المرور من إعدادات حسابك."
            );
        }

        try {

            await auth.updateUser(
                uid,
                {
                    password:
                        String(password)
                }
            );

            return {
                ok: true
            };

        } catch (e) {

            if (
                e.code ===
                "auth/user-not-found"
            ) {
                throw new HttpsError(
                    "not-found",
                    "المستخدم غير موجود."
                );
            }

            throw new HttpsError(
                "internal",
                e.message ||
                "تعذر تغيير كلمة المرور."
            );
        }
    }
);


/* ================================
   DELETE USER
================================ */

exports.deleteUser = onCall(
    {
        cors: [
            "http://127.0.0.1:5500",
            "http://localhost:5500"
        ]
    },
    async (request) => {

        await requireAdmin(request);

        const {
            uid
        } = request.data || {};

        if (!uid) {
            throw new HttpsError(
                "invalid-argument",
                "UID مطلوب."
            );
        }

        if (uid === request.auth.uid) {
            throw new HttpsError(
                "failed-precondition",
                "لا يمكنك حذف حسابك."
            );
        }

        try {

            await auth.deleteUser(uid);

        } catch (e) {

            if (
                e.code !==
                "auth/user-not-found"
            ) {
                throw new HttpsError(
                    "internal",
                    e.message ||
                    "تعذر حذف حساب الدخول."
                );
            }
        }

        try {

            await db
                .recursiveDelete(
                    db
                        .collection("users")
                        .doc(uid)
                );

        } catch (e) {

            throw new HttpsError(
                "internal",
                e.message ||
                "تم حذف الدخول ولكن حدث خطأ أثناء حذف بيانات المستخدم."
            );
        }

        return {
            ok: true
        };
    }
);