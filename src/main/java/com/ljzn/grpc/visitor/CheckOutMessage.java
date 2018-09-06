// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: visitor/visitor.message.proto

package com.ljzn.grpc.visitor;

/**
 * Protobuf type {@code VisitorSystem_cq.CheckOutMessage}
 */
public  final class CheckOutMessage extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:VisitorSystem_cq.CheckOutMessage)
    CheckOutMessageOrBuilder {
private static final long serialVersionUID = 0L;
  // Use CheckOutMessage.newBuilder() to construct.
  private CheckOutMessage(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private CheckOutMessage() {
    visitId_ = "";
    checkOutDeviceId_ = "";
    checkOutTime_ = 0L;
    belongId_ = 0;
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private CheckOutMessage(
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

            visitId_ = s;
            break;
          }
          case 18: {
            java.lang.String s = input.readStringRequireUtf8();

            checkOutDeviceId_ = s;
            break;
          }
          case 24: {

            checkOutTime_ = input.readInt64();
            break;
          }
          case 32: {

            belongId_ = input.readInt32();
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
    return com.ljzn.grpc.visitor.VisitorMessageOuterClass.internal_static_VisitorSystem_cq_CheckOutMessage_descriptor;
  }

  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.ljzn.grpc.visitor.VisitorMessageOuterClass.internal_static_VisitorSystem_cq_CheckOutMessage_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.ljzn.grpc.visitor.CheckOutMessage.class, com.ljzn.grpc.visitor.CheckOutMessage.Builder.class);
  }

  public static final int VISITID_FIELD_NUMBER = 1;
  private volatile java.lang.Object visitId_;
  /**
   * <pre>
   *访问ID
   * </pre>
   *
   * <code>string visitId = 1;</code>
   */
  public java.lang.String getVisitId() {
    java.lang.Object ref = visitId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      visitId_ = s;
      return s;
    }
  }
  /**
   * <pre>
   *访问ID
   * </pre>
   *
   * <code>string visitId = 1;</code>
   */
  public com.google.protobuf.ByteString
      getVisitIdBytes() {
    java.lang.Object ref = visitId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      visitId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int CHECKOUTDEVICEID_FIELD_NUMBER = 2;
  private volatile java.lang.Object checkOutDeviceId_;
  /**
   * <pre>
   *签离设备ID
   * </pre>
   *
   * <code>string checkOutDeviceId = 2;</code>
   */
  public java.lang.String getCheckOutDeviceId() {
    java.lang.Object ref = checkOutDeviceId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      checkOutDeviceId_ = s;
      return s;
    }
  }
  /**
   * <pre>
   *签离设备ID
   * </pre>
   *
   * <code>string checkOutDeviceId = 2;</code>
   */
  public com.google.protobuf.ByteString
      getCheckOutDeviceIdBytes() {
    java.lang.Object ref = checkOutDeviceId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      checkOutDeviceId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int CHECKOUTTIME_FIELD_NUMBER = 3;
  private long checkOutTime_;
  /**
   * <pre>
   *签离时间
   * </pre>
   *
   * <code>int64 checkOutTime = 3;</code>
   */
  public long getCheckOutTime() {
    return checkOutTime_;
  }

  public static final int BELONGID_FIELD_NUMBER = 4;
  private int belongId_;
  /**
   * <pre>
   *本系统分配的ID
   * </pre>
   *
   * <code>int32 belongId = 4;</code>
   */
  public int getBelongId() {
    return belongId_;
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
    if (!getVisitIdBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, visitId_);
    }
    if (!getCheckOutDeviceIdBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, checkOutDeviceId_);
    }
    if (checkOutTime_ != 0L) {
      output.writeInt64(3, checkOutTime_);
    }
    if (belongId_ != 0) {
      output.writeInt32(4, belongId_);
    }
    unknownFields.writeTo(output);
  }

  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!getVisitIdBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, visitId_);
    }
    if (!getCheckOutDeviceIdBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, checkOutDeviceId_);
    }
    if (checkOutTime_ != 0L) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt64Size(3, checkOutTime_);
    }
    if (belongId_ != 0) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(4, belongId_);
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
    if (!(obj instanceof com.ljzn.grpc.visitor.CheckOutMessage)) {
      return super.equals(obj);
    }
    com.ljzn.grpc.visitor.CheckOutMessage other = (com.ljzn.grpc.visitor.CheckOutMessage) obj;

    boolean result = true;
    result = result && getVisitId()
        .equals(other.getVisitId());
    result = result && getCheckOutDeviceId()
        .equals(other.getCheckOutDeviceId());
    result = result && (getCheckOutTime()
        == other.getCheckOutTime());
    result = result && (getBelongId()
        == other.getBelongId());
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
    hash = (37 * hash) + VISITID_FIELD_NUMBER;
    hash = (53 * hash) + getVisitId().hashCode();
    hash = (37 * hash) + CHECKOUTDEVICEID_FIELD_NUMBER;
    hash = (53 * hash) + getCheckOutDeviceId().hashCode();
    hash = (37 * hash) + CHECKOUTTIME_FIELD_NUMBER;
    hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
        getCheckOutTime());
    hash = (37 * hash) + BELONGID_FIELD_NUMBER;
    hash = (53 * hash) + getBelongId();
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.visitor.CheckOutMessage parseFrom(
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
  public static Builder newBuilder(com.ljzn.grpc.visitor.CheckOutMessage prototype) {
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
   * Protobuf type {@code VisitorSystem_cq.CheckOutMessage}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:VisitorSystem_cq.CheckOutMessage)
      com.ljzn.grpc.visitor.CheckOutMessageOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.ljzn.grpc.visitor.VisitorMessageOuterClass.internal_static_VisitorSystem_cq_CheckOutMessage_descriptor;
    }

    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.ljzn.grpc.visitor.VisitorMessageOuterClass.internal_static_VisitorSystem_cq_CheckOutMessage_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.ljzn.grpc.visitor.CheckOutMessage.class, com.ljzn.grpc.visitor.CheckOutMessage.Builder.class);
    }

    // Construct using com.ljzn.grpc.visitor.CheckOutMessage.newBuilder()
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
      visitId_ = "";

      checkOutDeviceId_ = "";

      checkOutTime_ = 0L;

      belongId_ = 0;

      return this;
    }

    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.ljzn.grpc.visitor.VisitorMessageOuterClass.internal_static_VisitorSystem_cq_CheckOutMessage_descriptor;
    }

    public com.ljzn.grpc.visitor.CheckOutMessage getDefaultInstanceForType() {
      return com.ljzn.grpc.visitor.CheckOutMessage.getDefaultInstance();
    }

    public com.ljzn.grpc.visitor.CheckOutMessage build() {
      com.ljzn.grpc.visitor.CheckOutMessage result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    public com.ljzn.grpc.visitor.CheckOutMessage buildPartial() {
      com.ljzn.grpc.visitor.CheckOutMessage result = new com.ljzn.grpc.visitor.CheckOutMessage(this);
      result.visitId_ = visitId_;
      result.checkOutDeviceId_ = checkOutDeviceId_;
      result.checkOutTime_ = checkOutTime_;
      result.belongId_ = belongId_;
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
      if (other instanceof com.ljzn.grpc.visitor.CheckOutMessage) {
        return mergeFrom((com.ljzn.grpc.visitor.CheckOutMessage)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.ljzn.grpc.visitor.CheckOutMessage other) {
      if (other == com.ljzn.grpc.visitor.CheckOutMessage.getDefaultInstance()) return this;
      if (!other.getVisitId().isEmpty()) {
        visitId_ = other.visitId_;
        onChanged();
      }
      if (!other.getCheckOutDeviceId().isEmpty()) {
        checkOutDeviceId_ = other.checkOutDeviceId_;
        onChanged();
      }
      if (other.getCheckOutTime() != 0L) {
        setCheckOutTime(other.getCheckOutTime());
      }
      if (other.getBelongId() != 0) {
        setBelongId(other.getBelongId());
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
      com.ljzn.grpc.visitor.CheckOutMessage parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (com.ljzn.grpc.visitor.CheckOutMessage) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private java.lang.Object visitId_ = "";
    /**
     * <pre>
     *访问ID
     * </pre>
     *
     * <code>string visitId = 1;</code>
     */
    public java.lang.String getVisitId() {
      java.lang.Object ref = visitId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        visitId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <pre>
     *访问ID
     * </pre>
     *
     * <code>string visitId = 1;</code>
     */
    public com.google.protobuf.ByteString
        getVisitIdBytes() {
      java.lang.Object ref = visitId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        visitId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <pre>
     *访问ID
     * </pre>
     *
     * <code>string visitId = 1;</code>
     */
    public Builder setVisitId(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      visitId_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     *访问ID
     * </pre>
     *
     * <code>string visitId = 1;</code>
     */
    public Builder clearVisitId() {
      
      visitId_ = getDefaultInstance().getVisitId();
      onChanged();
      return this;
    }
    /**
     * <pre>
     *访问ID
     * </pre>
     *
     * <code>string visitId = 1;</code>
     */
    public Builder setVisitIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      visitId_ = value;
      onChanged();
      return this;
    }

    private java.lang.Object checkOutDeviceId_ = "";
    /**
     * <pre>
     *签离设备ID
     * </pre>
     *
     * <code>string checkOutDeviceId = 2;</code>
     */
    public java.lang.String getCheckOutDeviceId() {
      java.lang.Object ref = checkOutDeviceId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        checkOutDeviceId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <pre>
     *签离设备ID
     * </pre>
     *
     * <code>string checkOutDeviceId = 2;</code>
     */
    public com.google.protobuf.ByteString
        getCheckOutDeviceIdBytes() {
      java.lang.Object ref = checkOutDeviceId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        checkOutDeviceId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <pre>
     *签离设备ID
     * </pre>
     *
     * <code>string checkOutDeviceId = 2;</code>
     */
    public Builder setCheckOutDeviceId(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      checkOutDeviceId_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     *签离设备ID
     * </pre>
     *
     * <code>string checkOutDeviceId = 2;</code>
     */
    public Builder clearCheckOutDeviceId() {
      
      checkOutDeviceId_ = getDefaultInstance().getCheckOutDeviceId();
      onChanged();
      return this;
    }
    /**
     * <pre>
     *签离设备ID
     * </pre>
     *
     * <code>string checkOutDeviceId = 2;</code>
     */
    public Builder setCheckOutDeviceIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      checkOutDeviceId_ = value;
      onChanged();
      return this;
    }

    private long checkOutTime_ ;
    /**
     * <pre>
     *签离时间
     * </pre>
     *
     * <code>int64 checkOutTime = 3;</code>
     */
    public long getCheckOutTime() {
      return checkOutTime_;
    }
    /**
     * <pre>
     *签离时间
     * </pre>
     *
     * <code>int64 checkOutTime = 3;</code>
     */
    public Builder setCheckOutTime(long value) {
      
      checkOutTime_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     *签离时间
     * </pre>
     *
     * <code>int64 checkOutTime = 3;</code>
     */
    public Builder clearCheckOutTime() {
      
      checkOutTime_ = 0L;
      onChanged();
      return this;
    }

    private int belongId_ ;
    /**
     * <pre>
     *本系统分配的ID
     * </pre>
     *
     * <code>int32 belongId = 4;</code>
     */
    public int getBelongId() {
      return belongId_;
    }
    /**
     * <pre>
     *本系统分配的ID
     * </pre>
     *
     * <code>int32 belongId = 4;</code>
     */
    public Builder setBelongId(int value) {
      
      belongId_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     *本系统分配的ID
     * </pre>
     *
     * <code>int32 belongId = 4;</code>
     */
    public Builder clearBelongId() {
      
      belongId_ = 0;
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


    // @@protoc_insertion_point(builder_scope:VisitorSystem_cq.CheckOutMessage)
  }

  // @@protoc_insertion_point(class_scope:VisitorSystem_cq.CheckOutMessage)
  private static final com.ljzn.grpc.visitor.CheckOutMessage DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.ljzn.grpc.visitor.CheckOutMessage();
  }

  public static com.ljzn.grpc.visitor.CheckOutMessage getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<CheckOutMessage>
      PARSER = new com.google.protobuf.AbstractParser<CheckOutMessage>() {
    public CheckOutMessage parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new CheckOutMessage(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<CheckOutMessage> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<CheckOutMessage> getParserForType() {
    return PARSER;
  }

  public com.ljzn.grpc.visitor.CheckOutMessage getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

