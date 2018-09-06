// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: metting/metting.service.proto

package com.ljzn.grpc.metting;

/**
 * Protobuf type {@code MettingSystem.MettingEmpInfoRequest}
 */
public  final class MettingEmpInfoRequest extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:MettingSystem.MettingEmpInfoRequest)
    MettingEmpInfoRequestOrBuilder {
private static final long serialVersionUID = 0L;
  // Use MettingEmpInfoRequest.newBuilder() to construct.
  private MettingEmpInfoRequest(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private MettingEmpInfoRequest() {
    mettingName_ = "";
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private MettingEmpInfoRequest(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    int mutable_bitField0_ = 0;
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          default: {
            if (!parseUnknownFieldProto3(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
          case 10: {
            java.lang.String s = input.readStringRequireUtf8();

            mettingName_ = s;
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.ljzn.grpc.metting.MettingService.internal_static_MettingSystem_MettingEmpInfoRequest_descriptor;
  }

  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.ljzn.grpc.metting.MettingService.internal_static_MettingSystem_MettingEmpInfoRequest_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.ljzn.grpc.metting.MettingEmpInfoRequest.class, com.ljzn.grpc.metting.MettingEmpInfoRequest.Builder.class);
  }

  public static final int METTINGNAME_FIELD_NUMBER = 1;
  private volatile java.lang.Object mettingName_;
  /**
   * <code>string mettingName = 1;</code>
   */
  public java.lang.String getMettingName() {
    java.lang.Object ref = mettingName_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      mettingName_ = s;
      return s;
    }
  }
  /**
   * <code>string mettingName = 1;</code>
   */
  public com.google.protobuf.ByteString
      getMettingNameBytes() {
    java.lang.Object ref = mettingName_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      mettingName_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  private byte memoizedIsInitialized = -1;
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (!getMettingNameBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, mettingName_);
    }
    unknownFields.writeTo(output);
  }

  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!getMettingNameBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, mettingName_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof com.ljzn.grpc.metting.MettingEmpInfoRequest)) {
      return super.equals(obj);
    }
    com.ljzn.grpc.metting.MettingEmpInfoRequest other = (com.ljzn.grpc.metting.MettingEmpInfoRequest) obj;

    boolean result = true;
    result = result && getMettingName()
        .equals(other.getMettingName());
    result = result && unknownFields.equals(other.unknownFields);
    return result;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + METTINGNAME_FIELD_NUMBER;
    hash = (53 * hash) + getMettingName().hashCode();
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.metting.MettingEmpInfoRequest parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(com.ljzn.grpc.metting.MettingEmpInfoRequest prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code MettingSystem.MettingEmpInfoRequest}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:MettingSystem.MettingEmpInfoRequest)
      com.ljzn.grpc.metting.MettingEmpInfoRequestOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.ljzn.grpc.metting.MettingService.internal_static_MettingSystem_MettingEmpInfoRequest_descriptor;
    }

    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.ljzn.grpc.metting.MettingService.internal_static_MettingSystem_MettingEmpInfoRequest_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.ljzn.grpc.metting.MettingEmpInfoRequest.class, com.ljzn.grpc.metting.MettingEmpInfoRequest.Builder.class);
    }

    // Construct using com.ljzn.grpc.metting.MettingEmpInfoRequest.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    public Builder clear() {
      super.clear();
      mettingName_ = "";

      return this;
    }

    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.ljzn.grpc.metting.MettingService.internal_static_MettingSystem_MettingEmpInfoRequest_descriptor;
    }

    public com.ljzn.grpc.metting.MettingEmpInfoRequest getDefaultInstanceForType() {
      return com.ljzn.grpc.metting.MettingEmpInfoRequest.getDefaultInstance();
    }

    public com.ljzn.grpc.metting.MettingEmpInfoRequest build() {
      com.ljzn.grpc.metting.MettingEmpInfoRequest result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    public com.ljzn.grpc.metting.MettingEmpInfoRequest buildPartial() {
      com.ljzn.grpc.metting.MettingEmpInfoRequest result = new com.ljzn.grpc.metting.MettingEmpInfoRequest(this);
      result.mettingName_ = mettingName_;
      onBuilt();
      return result;
    }

    public Builder clone() {
      return (Builder) super.clone();
    }
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return (Builder) super.setField(field, value);
    }
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return (Builder) super.clearField(field);
    }
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return (Builder) super.clearOneof(oneof);
    }
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return (Builder) super.setRepeatedField(field, index, value);
    }
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return (Builder) super.addRepeatedField(field, value);
    }
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof com.ljzn.grpc.metting.MettingEmpInfoRequest) {
        return mergeFrom((com.ljzn.grpc.metting.MettingEmpInfoRequest)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.ljzn.grpc.metting.MettingEmpInfoRequest other) {
      if (other == com.ljzn.grpc.metting.MettingEmpInfoRequest.getDefaultInstance()) return this;
      if (!other.getMettingName().isEmpty()) {
        mettingName_ = other.mettingName_;
        onChanged();
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    public final boolean isInitialized() {
      return true;
    }

    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      com.ljzn.grpc.metting.MettingEmpInfoRequest parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (com.ljzn.grpc.metting.MettingEmpInfoRequest) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private java.lang.Object mettingName_ = "";
    /**
     * <code>string mettingName = 1;</code>
     */
    public java.lang.String getMettingName() {
      java.lang.Object ref = mettingName_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        mettingName_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string mettingName = 1;</code>
     */
    public com.google.protobuf.ByteString
        getMettingNameBytes() {
      java.lang.Object ref = mettingName_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        mettingName_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string mettingName = 1;</code>
     */
    public Builder setMettingName(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      mettingName_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string mettingName = 1;</code>
     */
    public Builder clearMettingName() {
      
      mettingName_ = getDefaultInstance().getMettingName();
      onChanged();
      return this;
    }
    /**
     * <code>string mettingName = 1;</code>
     */
    public Builder setMettingNameBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      mettingName_ = value;
      onChanged();
      return this;
    }
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFieldsProto3(unknownFields);
    }

    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:MettingSystem.MettingEmpInfoRequest)
  }

  // @@protoc_insertion_point(class_scope:MettingSystem.MettingEmpInfoRequest)
  private static final com.ljzn.grpc.metting.MettingEmpInfoRequest DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.ljzn.grpc.metting.MettingEmpInfoRequest();
  }

  public static com.ljzn.grpc.metting.MettingEmpInfoRequest getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<MettingEmpInfoRequest>
      PARSER = new com.google.protobuf.AbstractParser<MettingEmpInfoRequest>() {
    public MettingEmpInfoRequest parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new MettingEmpInfoRequest(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<MettingEmpInfoRequest> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<MettingEmpInfoRequest> getParserForType() {
    return PARSER;
  }

  public com.ljzn.grpc.metting.MettingEmpInfoRequest getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

