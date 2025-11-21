package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class CreateOperationResponse implements Parcelable {
    /** The binder representing the newly created operation. */
    public IKeystoreOperation iOperation;
    /**
     * A challenge associated with the newly created operation. If this field is
     * set.
     * it indicates that the operation has yet to be authorized by the user.
     */
    public OperationChallenge operationChallenge;
    /**
     * Optional parameters returned from the KeyMint operation. This may contain a
     * nonce
     * or an initialization vector IV for operations that use them.
     */
    public KeyParameters parameters;
    /**
     * An optional opaque blob. If the key given to ISecurityLevel::CreateOperation
     * uses Domain::BLOB and was upgraded, then this field is present, and
     * represents the
     * upgraded version of that key.
     */
    public byte[] upgradedBlob;

    public static final android.os.Parcelable.Creator<CreateOperationResponse> CREATOR = new android.os.Parcelable.Creator<CreateOperationResponse>() {
        public CreateOperationResponse createFromParcel(android.os.Parcel _aidl_source) {
            throw new RuntimeException("");
        }

        public CreateOperationResponse[] newArray(int _aidl_size) {
            throw new RuntimeException("");
        }

    };

    @Override
    public final void writeToParcel(android.os.Parcel _aidl_parcel, int _aidl_flag) {
        throw new RuntimeException("");
    }

    public final void readFromParcel(android.os.Parcel _aidl_parcel) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    private int describeContents(Object _v) {
        throw new RuntimeException("");
    }
}
