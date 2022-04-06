use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::sync::Mutex;
use libc::{c_void};
use p256::elliptic_curve::sec1::EncodedPoint;
use p256::NistP256;

use thiserror::Error;
pub type Result<T = ()> = std::result::Result<T, Error>;

use tss2::{
    FAPI_CONTEXT, TSS2_RC, TSS2_RC_SUCCESS, ESYS_TR, FAPI_ESYSBLOB_CONTEXTLOAD, TPMS_CONTEXT,
    TSS2_TCTI_CONTEXT, ESYS_CONTEXT, TPM2B_ECC_POINT, ESYS_TR_PASSWORD, ESYS_TR_NONE,
    TPM2B_PUBLIC, TPM2B_NAME,
    UINT16, BYTE,
    Tss2_MU_TPMS_CONTEXT_Unmarshal,
    Esys_Initialize, Esys_ContextLoad, Esys_ECDH_ZGen, Esys_FlushContext, Esys_Finalize, Esys_ReadPublic,
    Fapi_Initialize, Fapi_Finalize, Fapi_GetEsysBlob, Fapi_GetTcti, Fapi_Sign
};


#[derive(Debug, Error)]
pub enum Error {
    #[error("function {0} returned error code {1}")]
    TPMError(String, u32),

    #[error("wrong key path")]
    WrongKeyPath,
}

impl Error {
    pub fn tpm_error(func: String, code: u32) -> crate::Error {
        Self::TPMError(func, code).into()
    }

    pub fn wrong_key_path() -> crate::Error {
        Self::WrongKeyPath.into()
    }
}

static mut TPM_CTX: Option<Mutex<*mut FAPI_CONTEXT>> = None;

fn tpm<'a>() -> &'a Mutex<*mut FAPI_CONTEXT> {
    unsafe { TPM_CTX.as_ref().unwrap() }
}

fn with_tpm<F, R>(f: F) -> R
    where
        F: FnOnce(*mut FAPI_CONTEXT) -> R,
{
    let tpm_ctx = tpm().lock().unwrap();
    f(*tpm_ctx)
}

pub fn tpm_init() -> Result {
    unsafe {
        let mut tpm_ctx: *mut FAPI_CONTEXT = MaybeUninit::uninit().assume_init();
        let res = Fapi_Initialize(&mut tpm_ctx as *mut *mut FAPI_CONTEXT, null_mut());
        if res != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_Initialize"), res));
        }

        TPM_CTX = Some(Mutex::new(tpm_ctx));
    }

    Ok(())
}

pub fn tpm_deinit() {
    unsafe {
        let mut tpm_ctx = *tpm().lock().unwrap();
        Fapi_Finalize(&mut tpm_ctx);
        TPM_CTX = None;
    }
}

fn free_esys_resources (esys_ctx: &mut *mut ESYS_CONTEXT, esys_key_handle: ESYS_TR) -> Result {
    unsafe {
        if esys_key_handle != u32::MAX {
            let res = Esys_FlushContext(*esys_ctx, esys_key_handle);
            if res != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_FlushContext"), res));
            }
        }

        Esys_Finalize(&mut *esys_ctx);
    }

    Ok(())
}

pub fn public_key(key_path: &String) -> Result<Vec<u8>> {
    unsafe {
        let mut result: TSS2_RC = TSS2_RC_SUCCESS;
        let mut esys_key_handle: ESYS_TR = u32::MAX;
        let mut blob_type: u8 = 0;
        let mut esys_blob: *mut u8 = null_mut();
        let mut blob_sz: tss2::size_t = 0;
        let mut offset: tss2::size_t = 0;
        result = with_tpm(|tpm_ctx| Fapi_GetEsysBlob(tpm_ctx,
                                                     CString::new(key_path.as_bytes()).unwrap().as_ptr(),
                                                     &mut blob_type as *mut u8,
                                                     &mut esys_blob as *mut *mut u8,
                                                     &mut blob_sz as *mut tss2::size_t));
        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_GetEsysBlob"), result));
        }
        if blob_type != FAPI_ESYSBLOB_CONTEXTLOAD as u8 {
            return Err(Error::wrong_key_path());
        }

        let mut key_context: TPMS_CONTEXT = MaybeUninit::uninit().assume_init();
        result = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob,
                                                blob_sz,
                                                &mut offset as *mut tss2::size_t,
                                                &mut key_context as *mut TPMS_CONTEXT);
        libc::free(esys_blob as *mut c_void);

        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Tss2_MU_TPMS_CONTEXT_Unmarshal"), result));
        }

        let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
        result = with_tpm(|tpm_ctx| Fapi_GetTcti(tpm_ctx, &mut tcti_ctx as *mut *mut TSS2_TCTI_CONTEXT));
        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_GetTcti"), result));
        }

        let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();
        result = Esys_Initialize(&mut esys_ctx as *mut *mut ESYS_CONTEXT, tcti_ctx, null_mut());
        if result != TSS2_RC_SUCCESS {
            free_esys_resources(&mut esys_ctx, esys_key_handle)?;
            return Err(Error::tpm_error(String::from("Esys_Initialize"), result));
        }

        result = Esys_ContextLoad(esys_ctx, &mut key_context as *mut TPMS_CONTEXT, &mut esys_key_handle as *mut ESYS_TR);
        if result != TSS2_RC_SUCCESS {
            free_esys_resources(&mut esys_ctx, esys_key_handle)?;
            return Err(Error::tpm_error(String::from("Esys_ContextLoad"), result));
        }

        let mut public_part: *mut TPM2B_PUBLIC = null_mut();
        let mut public_name: *mut TPM2B_NAME = null_mut();
        let mut qualif_name: *mut TPM2B_NAME = null_mut();
        result = Esys_ReadPublic(esys_ctx,
                                 esys_key_handle,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 &mut public_part as *mut *mut TPM2B_PUBLIC,
                                 &mut public_name as *mut *mut TPM2B_NAME,
                                 &mut qualif_name as *mut *mut TPM2B_NAME);
        if result != TSS2_RC_SUCCESS {
            free_esys_resources(&mut esys_ctx, esys_key_handle)?;
            return Err(Error::tpm_error(String::from("Esys_ReadPublic"), result));
        }

        let ecc_point = (*public_part).publicArea.unique.ecc;
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(&ecc_point.x.buffer.as_slice()[..ecc_point.x.size as usize]);
        key_bytes.extend_from_slice(&ecc_point.y.buffer.as_slice()[..ecc_point.y.size as usize]);

        libc::free(public_part as *mut c_void);
        libc::free(public_name as *mut c_void);
        libc::free(qualif_name as *mut c_void);

        free_esys_resources(&mut esys_ctx, esys_key_handle)?;

        Ok(key_bytes)
    }
}

pub fn ecdh(point: EncodedPoint<NistP256>, path: &String) -> Result<Vec<u8>> {
    unsafe {
        let mut result: TSS2_RC;
        let mut esys_key_handle: ESYS_TR = u32::MAX;
        let mut blob_type: u8 = 0;
        let mut esys_blob: *mut u8 = null_mut();
        let mut blob_sz: tss2::size_t = 0;
        let mut offset: tss2::size_t = 0;

        result = with_tpm(|tpm_ctx| {
            Fapi_GetEsysBlob(tpm_ctx,
                             CString::new(path.as_bytes()).unwrap().as_ptr(),
                             &mut blob_type as *mut u8,
                             &mut esys_blob as *mut *mut u8,
                             &mut blob_sz as *mut tss2::size_t)
        });

        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_GetEsysBlob"), result));
        }

        if blob_type != FAPI_ESYSBLOB_CONTEXTLOAD as u8 {
            return Err(Error::wrong_key_path());
        }

        let mut key_context: TPMS_CONTEXT = MaybeUninit::uninit().assume_init();
        result = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob, blob_sz, &mut offset as *mut tss2::size_t, &mut key_context as *mut TPMS_CONTEXT);
        libc::free(esys_blob as *mut c_void);
        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Tss2_MU_TPMS_CONTEXT_Unmarshal"), result));
        }

        let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
        result = with_tpm(|tpm_ctx| Fapi_GetTcti(tpm_ctx, &mut tcti_ctx as *mut *mut TSS2_TCTI_CONTEXT));
        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_GetTcti"), result));
        }

        let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();
        result = Esys_Initialize(&mut esys_ctx as *mut *mut ESYS_CONTEXT, tcti_ctx, null_mut());
        if result != TSS2_RC_SUCCESS {
            free_esys_resources(&mut esys_ctx, esys_key_handle)?;
            return Err(Error::tpm_error(String::from("Esys_Initialize"), result));
        }

        result = Esys_ContextLoad(esys_ctx, &mut key_context as *mut TPMS_CONTEXT, &mut esys_key_handle as *mut ESYS_TR);
        if result != TSS2_RC_SUCCESS {
            free_esys_resources(&mut esys_ctx, esys_key_handle)?;
            return Err(Error::tpm_error(String::from("Esys_ContextLoad"), result));
        }

        let mut secret: *mut TPM2B_ECC_POINT = null_mut();
        let mut pub_point: TPM2B_ECC_POINT = MaybeUninit::uninit().assume_init();
        let x_len = point.x().unwrap().len();
        pub_point.point.x.size = x_len as UINT16;
        pub_point.point.x.buffer[..x_len].copy_from_slice(point.x().unwrap().as_slice());

        let y_len = point.y().unwrap().len();
        pub_point.point.y.size = y_len as UINT16;
        pub_point.point.y.buffer[..y_len].copy_from_slice(point.y().unwrap().as_slice());
        pub_point.size = pub_point.point.x.size + pub_point.point.y.size;

        result = Esys_ECDH_ZGen(esys_ctx,
                                esys_key_handle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &mut pub_point as *mut TPM2B_ECC_POINT,
                                &mut secret as *mut *mut TPM2B_ECC_POINT);


        if result != TSS2_RC_SUCCESS {
            free_esys_resources(&mut esys_ctx, esys_key_handle)?;
            return Err(Error::tpm_error(String::from("Esys_ECDH_ZGen"), result));
        }

        free_esys_resources(&mut esys_ctx, esys_key_handle)?;

        let mut shared_secret_bytes = Vec::new();
        shared_secret_bytes.extend_from_slice(&(*secret).point.x.buffer.as_slice()[..(*secret).point.x.size as usize]);
        shared_secret_bytes.extend_from_slice(&(*secret).point.y.buffer.as_slice()[..(*secret).point.y.size as usize]);

        return Ok(shared_secret_bytes);
    }
}

pub fn sign(path: &String, digest: Vec<u8>) -> Result<Vec<u8>> {
    unsafe {
        let mut raw_signature: *mut u8 = null_mut();
        let mut signature_sz: tss2::size_t = 0;
        let mut public_key: *mut c_char = null_mut();
        let mut certificate: *mut c_char = null_mut();
        let result = with_tpm(|tpm_ctx| Fapi_Sign(tpm_ctx,
                                                  CString::new(path.as_bytes()).unwrap().as_ptr(),
                                                  null_mut(),
                                                  digest.as_ptr(),
                                                  digest.len() as tss2::size_t,
                                                  &mut raw_signature as *mut *mut u8,
                                                  &mut signature_sz as *mut tss2::size_t,
                                                  &mut public_key as *mut *mut c_char,
                                                  &mut certificate as *mut *mut c_char));

        if result != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_Sign"), result));
        }

        libc::free(public_key as *mut c_void);
        libc::free(certificate as *mut c_void);

        let sign_slice = std::slice::from_raw_parts(raw_signature, signature_sz as usize).to_vec();
        libc::free(raw_signature as *mut c_void);

        return Ok(sign_slice);
    }

}


