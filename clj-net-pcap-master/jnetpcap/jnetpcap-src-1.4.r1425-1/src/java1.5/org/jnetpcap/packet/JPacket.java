/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.JThreadLocal;

/**
 * A native packet buffer object. This class references both packet data buffer
 * and decoded native packet structure. JPacket class is a subclass of a more
 * general JBuffer providing full access to raw packet buffer data. It also has
 * a reference to JPacket.State object which is peered, associated with, a
 * native packet state structure generated by the packet scanner, the JScanner.
 * <p>
 * The packet interface provides numerous methods for accessing the decoded
 * information. To check if any particular header is found within the packet's
 * data buffer at the time the packet was scanned, the user can use
 * {@link #hasHeader} methods. The method returns true if a particular header is
 * found within the packet data buffer, otherwise false. A convenience method
 * {@link #hasHeader(JHeader)} exists that performs both an existence check and
 * initializes the header instance supplied to point at the header within the
 * packet.
 * </p>
 * <p>
 * There are also numerous peer and deep copy methods. The peering methods do
 * not copy any buffers but simply re-orient the pointers to point at the source
 * peer structures to destination peer. The deep copy methods do copy physical
 * data out of buffers and entire structures using native copy functions, not in
 * java space.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JPacket extends JBuffer implements JHeaderAccessor,
		Iterable<JHeader> {

	/**
	 * Class maintains the decoded packet state. The class is peered with
	 * <code>struct packet_state_t</code>
	 * 
	 * <pre>
	 * typedef struct packet_state_t {
	 * 	uint64_t pkt_header_map; // bit map of presence of headers
	 * 	char *pkt_data; // packet data buffer
	 * 	int32_t pkt_header_count; // total number of headers found
	 * 
	 * 	// Keep track of how many instances of each header we have
	 * 	uint8_t pkt_instance_counts[MAX_ID_COUNT];
	 * 	header_t pkt_headers[]; // One per header + 1 more for payload
	 * } packet_t;
	 * </pre>
	 * 
	 * and <code>struct header_t</code>
	 * 
	 * <pre>
	 * typedef struct header_t {
	 * 	int32_t hdr_id; // header ID
	 * 	uint32_t hdr_offset; // offset into the packet_t-&gt;data buffer
	 * 	int32_t hdr_length; // length of the header in packet_t-&gt;data buffer
	 * } header_t;
	 * 
	 * </pre>
	 * 
	 * <p>
	 * The methods in this <code>State</code> provide 3 sets of functions.
	 * Looking up global state of the packet found in packet_state_t structure,
	 * looking up header information in <code>struct header_t</code> by header
	 * ID retrieved from JRegistry and instance numbers, looking up header
	 * information by direct indexes into native maps and arrays. Instance
	 * numbers specify which instance of the header, if more than 1 exists in a
	 * packet. For example if there is a packet with 2 Ip4 headers such as
	 * 
	 * <pre>
	 * Ethernet-&gt;Ip4-&gt;Snmp-&gt;Ip4 
	 * or 
	 * Ethernet-&gt;Ip4-&gt;Ip4 (IP tunneled IP)
	 * </pre>
	 * 
	 * the first Ip4 header is instance 0 and the second Ip4 header is instance
	 * 2. You can use the method {@link #getInstanceCount(int)} to learn how
	 * many instance headers exists. That information is stored in the
	 * packet_state_t structure for efficiency.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class State extends JStruct {

		/**
		 * Flag which is set when the packet that was decoded was truncated and
		 * not the original length seen on the wire.
		 */
		public final static int FLAG_TRUNCATED = 0x01;

		/** The Constant STRUCT_NAME. */
		public final static String STRUCT_NAME = "packet_state_t";

		/**
		 * Sizeof.
		 * 
		 * @param count
		 *            header counter, number of headers to calaculate in
		 * @return size in bytes
		 */
		public static native int sizeof(int count);

		/** The flow key. */
		private JFlowKey flowKey;

		/**
		 * Instantiates a new state.
		 * 
		 * @param size
		 *            the size
		 */
		public State(int size) {
			super(STRUCT_NAME, size);
		}

		/**
		 * Instantiates a new state.
		 * 
		 * @param type
		 *            the type
		 */
		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		/**
		 * Cleanup.
		 * 
		 * @see org.jnetpcap.nio.JMemory#cleanup()
		 */
		@Override
		public void cleanup() {
			super.cleanup();
		}

		/**
		 * Find header index.
		 * 
		 * @param id
		 *            the id
		 * @return the int
		 */
		public int findHeaderIndex(int id) {
			return findHeaderIndex(id, 0);
		}

		/**
		 * Find header index.
		 * 
		 * @param id
		 *            the id
		 * @param instance
		 *            the instance
		 * @return the int
		 */
		public native int findHeaderIndex(int id, int instance);

		/**
		 * Gets the 64 bit header map.
		 * 
		 * @param index
		 *            TODO: remove index, its no longer used natively
		 * @return the 64 bit header map
		 */
		public native long get64BitHeaderMap(int index);

		/**
		 * Gets the 32-bit counter that contains packet's flags in
		 * packet_state_t structure.
		 * 
		 * @return bit flags for this packet
		 */
		public native int getFlags();

		/**
		 * Gets the flow key.
		 * 
		 * @return the flow key
		 */
		public JFlowKey getFlowKey() {
			if (this.flowKey == null) {
				this.flowKey = new JFlowKey();
			}

			peerFlowKey();

			return this.flowKey;
		}

		/**
		 * The frame number is assigned by the scanner at the time of the scan.
		 * Therefore number is only unique within the same scanner.
		 * 
		 * @return frame number
		 */
		public native long getFrameNumber();

		/**
		 * Gets the header count.
		 * 
		 * @return the header count
		 */
		public native int getHeaderCount();

		/**
		 * Gets the header id by index.
		 * 
		 * @param index
		 *            the index
		 * @return the header id by index
		 */
		public native int getHeaderIdByIndex(int index);

		/**
		 * A convenience method that gets the length in the packet buffer of the
		 * header at specified index. Typically header information is retrieved
		 * using JHeader.State structure which can access all available header
		 * information.
		 * 
		 * @param index
		 *            header index
		 * @return length in bytes of the header
		 */
		public native int getHeaderLengthByIndex(int index);

		/**
		 * A convenience method that gets the offset into the packet buffer of
		 * the header at specified index. Typically header information is
		 * retrieved using JHeader.State structure which can access all
		 * available header information.
		 * 
		 * @param index
		 *            header index
		 * @return offset in bytes of the start of the header
		 */
		public native int getHeaderOffsetByIndex(int index);

		/**
		 * Gets the instance count.
		 * 
		 * @param id
		 *            the id
		 * @return the instance count
		 */
		public native int getInstanceCount(int id);

		/**
		 * Gets the packet's wire length.
		 * 
		 * @return original length of the packet
		 */
		public native int getWirelen();

		/**
		 * Peer.
		 * 
		 * @param peer
		 *            the peer
		 * @return the int
		 * @throws PeeringException
		 *             the peering exception
		 * @see org.jnetpcap.nio.JMemory#peer(java.nio.ByteBuffer)
		 */
		@Override
		public int peer(ByteBuffer peer) throws PeeringException {
			int r = super.peer(peer);
			peerFlowKey();
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *            the peer
		 * @return the int
		 */
		public int peer(JBuffer peer) {
			int r = super.peer(peer, 0, size());

			peerFlowKey();
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *            the peer
		 * @param offset
		 *            the offset
		 * @param length
		 *            the length
		 * @return the int
		 * @throws IndexOutOfBoundsException
		 *             the index out of bounds exception
		 */
		public int peer(JBuffer peer, int offset, int length)
				throws IndexOutOfBoundsException {
			int r = super.peer(peer, offset, length);

			peerFlowKey();
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param memory
		 *            the memory
		 * @param offset
		 *            the offset
		 * @return the int
		 */
		public int peer(JMemory memory, int offset) {
			int r = super.peer(memory, offset, size());

			peerFlowKey();
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *            the peer
		 * @param offset
		 *            the offset
		 * @param length
		 *            the length
		 * @return the int
		 * @throws IndexOutOfBoundsException
		 *             the index out of bounds exception
		 */
		public int peer(JMemoryPool.Block peer, int offset, int length)
				throws IndexOutOfBoundsException {
			int r = super.peer(peer, offset, length);

			peerFlowKey();
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *            the peer
		 * @return the int
		 */
		public int peer(State peer) {
			int r = super.peer(peer, 0, size());

			peerFlowKey();
			return r;
		}

		private void peerFlowKey() {
			if (this.flowKey != null) {
				this.flowKey.peer(this);
			}
		}

		/**
		 * Peer header by id.
		 * 
		 * @param id
		 *            the id
		 * @param instance
		 *            the instance
		 * @param dst
		 *            the dst
		 * @return the int
		 */
		public native int peerHeaderById(int id, int instance, JHeader.State dst);

		/**
		 * Peer header by index.
		 * 
		 * @param index
		 *            the index
		 * @param dst
		 *            the dst
		 * @return the int
		 * @throws IndexOutOfBoundsException
		 *             the index out of bounds exception
		 */
		public native int peerHeaderByIndex(int index, JHeader.State dst)
				throws IndexOutOfBoundsException;

		/**
		 * Peers this packet's state to buffer.
		 * 
		 * @param buffer
		 *            source buffer
		 * @param offset
		 *            offset into the buffer
		 * @return number of bytes peered
		 */
		public int peerTo(JBuffer buffer, int offset) {
			int r = super.peer(buffer, offset, size());

			peerFlowKey();
			return r;
		}

		/**
		 * Peers this packet's state to buffer.
		 * 
		 * @param buffer
		 *            source buffer
		 * @param offset
		 *            offset into the buffer
		 * @param size
		 *            specifies the number of bytes to peer
		 * @return number of bytes peered
		 */
		public int peerTo(JBuffer buffer, int offset, int size) {
			int r = super.peer(buffer, offset, size);

			peerFlowKey();
			return r;
		}

		/**
		 * Peer to.
		 * 
		 * @param state
		 *            the state
		 * @param offset
		 *            the offset
		 * @return the int
		 */
		public int peerTo(State state, int offset) {
			int r = super.peer(state, offset, state.size());

			peerFlowKey();
			return r;
		}

		/**
		 * Sets the 32-bit counter with packet flags.
		 * 
		 * @param flags
		 *            bit flags for this packet
		 */
		public native void setFlags(int flags);

		/**
		 * Sets the packet's wire length.
		 * 
		 * @param length
		 *            the original length of the packet before truncation
		 */
		public native void setWirelen(int length);

		/**
		 * Dump packet_state_t structure and its sub structures to textual debug
		 * output
		 * <p>
		 * Explanation:
		 * 
		 * <pre>
		 * sizeof(packet_state_t)=16
		 * sizeof(header_t)=8 and *4=32
		 * pkt_header_map=0x1007         // bitmap, each bit represets a header
		 * pkt_header_count=4            // how many header found
		 * // per header information (4 header found in this example)
		 * pkt_headers[0]=&lt;hdr_id=1  ETHERNET ,hdr_offset=0  ,hdr_length=14&gt;
		 * pkt_headers[1]=&lt;hdr_id=2  IP4      ,hdr_offset=14 ,hdr_length=60&gt;
		 * pkt_headers[2]=&lt;hdr_id=12 ICMP     ,hdr_offset=74 ,hdr_length=2&gt;
		 * pkt_headers[3]=&lt;hdr_id=0  PAYLOAD  ,hdr_offset=76 ,hdr_length=62&gt;
		 * 
		 * // hdr_id = numerical ID of the header, asssigned by JRegistry
		 * // hdr_offset = offset in bytes into the packet buffer
		 * // hdr_length = length in bytes of the entire header
		 * </pre>
		 * 
		 * Packet state is made up of 2 structures: packet_stat_t and an array
		 * of header_t, one per header. Total size in bytes is all of the header
		 * structures combined, that is 16 + 32 = 48 bytes. Each bit in the
		 * header_map represents the presence of that header type. The index of
		 * the bit is the numerical ID of the header. If 2 headers of the same
		 * type are present, they are both represented by a single bit in the
		 * bitmap. This way the implementation JPacket.hasHeader(int id) is a
		 * simple bit operation to test if the header is present or not.
		 * </p>
		 * 
		 * @return multiline string containing dump of the entire structure
		 */
		@Override
		public String toDebugString() {

			return super.toDebugString() + "\n" + toDebugStringJPacketState();
		}

		/**
		 * To debug string j packet state.
		 * 
		 * @return the string
		 */
		private native String toDebugStringJPacketState();

		/**
		 * Transfer to.
		 * 
		 * @param dst
		 *            the dst
		 * @param dstOffset
		 *            the dst offset
		 * @return the int
		 */
		public int transferTo(byte[] dst, int dstOffset) {
			return super.transferTo(dst, 0, size(), dstOffset);
		}

		/**
		 * Transfer to.
		 * 
		 * @param dst
		 *            the dst
		 * @param srcOffset
		 *            the src offset
		 * @param length
		 *            the length
		 * @param dstOffset
		 *            the dst offset
		 * @return the int
		 * @see org.jnetpcap.nio.JMemory#transferTo(byte[], int, int, int)
		 */
		@Override
		public int transferTo(byte[] dst, int srcOffset, int length,
				int dstOffset) {
			return super.transferTo(dst, srcOffset, size(), dstOffset);
		}

		/**
		 * Transfer to.
		 * 
		 * @param dst
		 *            the dst
		 * @param srcOffset
		 *            the src offset
		 * @param length
		 *            the length
		 * @param dstOffset
		 *            the dst offset
		 * @return the int
		 * @see org.jnetpcap.nio.JMemory#transferTo(org.jnetpcap.nio.JBuffer,
		 *      int, int, int)
		 */
		@Override
		public int transferTo(JBuffer dst, int srcOffset, int length,
				int dstOffset) {
			return super.transferTo(dst, srcOffset, size(), dstOffset);
		}

		/**
		 * Transfer to.
		 * 
		 * @param dst
		 *            the dst
		 * @return the int
		 */
		public int transferTo(State dst) {
			return super.transferTo(dst, 0, size(), 0);
		}
	}

	/**
	 * Default number of headers used when calculating memory requirements for
	 * an empty packet state structure. This value will be multiplied by the
	 * sizeof(header_t) structure and added to the size of the packet_t
	 * strcutre.
	 */
	public final static int DEFAULT_STATE_HEADER_COUNT = 20;

	/** Default scanner used to scan a packet per user request. */
	protected static JThreadLocal<JScanner> defaultScanner;

	/** The header pool. */
	private static JHeaderPool headerPool = new JHeaderPool();

	/** The out. */
	private static JFormatter out = new TextFormatter(new StringBuilder());
	private static ThreadLocal<TextFormatter> formatterPool =
			new ThreadLocal<TextFormatter>() {

				@Override
				protected TextFormatter initialValue() {
					return new TextFormatter(new StringBuilder());
				}

			};

	/**
	 * Packet's default memory pool out of which allocates memory for deep
	 * copies.
	 */
	protected static JMemoryPool pool = new JMemoryPool();

	/**
	 * Gets the default header pool.
	 * 
	 * @return the default header pool
	 */
	public static JHeaderPool getDefaultHeaderPool() {
		return headerPool;
	}

	/**
	 * Returns the default scanner for all packets
	 * 
	 * @return the current default scanner
	 */
	public static JScanner getDefaultScanner() {
		if (defaultScanner == null) {
			synchronized (JScanner.class) {
				if (defaultScanner == null) {
					defaultScanner = new JThreadLocal<JScanner>(JScanner.class);
				}
			}
		}
		return defaultScanner.get();
	}

	/**
	 * Gets the current internal packet formatter used in the {@link #toString}
	 * method.
	 * 
	 * @return current formatter
	 */
	public static JFormatter getFormatter() {
		return JPacket.out;
	}

	/**
	 * Gets the current memory allocation memory pool.
	 * 
	 * @return current memory pool
	 */
	public static JMemoryPool getMemoryPool() {
		return pool;
	}

	/**
	 * Sets the default header pool.
	 * 
	 * @param headerPool
	 *            the new default header pool
	 */
	public static void setDefaultHeaderPool(JHeaderPool headerPool) {
		JPacket.headerPool = headerPool;
	}

	/**
	 * Replaced the default formatter for formatting output in the.
	 * 
	 * @param out
	 *            new formatter {@link #toString} method. The new formatter will
	 *            be used by default for all packets. The formatter should
	 *            internally build a string that will be returned with
	 *            out.toString() method call to get meaningful output.
	 */
	public static void setFormatter(JFormatter out) {
		JPacket.out = out;
	}

	/**
	 * Replaces the default memory allocation mechanism with user supplied one.
	 * 
	 * @param pool
	 *            new memory pool to use.
	 */
	public static void setMemoryPool(JMemoryPool pool) {
		JPacket.pool = pool;
	}

	/**
	 * Shutdown.
	 */
	public static void shutdown() {
		defaultScanner = null;
		pool = null;
	}

	/**
	 * The allocated memory buffer. Initially this buffer is empty, but may be
	 * peered with allocated memory for internal usage such as copying header,
	 * state and data into a single buffer
	 */
	protected final JBuffer memory = new JBuffer(Type.POINTER);

	/** Packet's state structure. */
	protected final State state = new State(Type.POINTER);

	/**
	 * Allocates a memory block and peers both the state and data buffer with
	 * it. The size parameter has to be big enough to hold both state and data
	 * for the packet.
	 * 
	 * @param size
	 *            amount of memory to allocate for packet data
	 * @param state
	 *            size of the state
	 */
	public JPacket(int size, int state) {
		super(Type.POINTER);
		
		order(ByteOrder.BIG_ENDIAN);

		allocate(size + state);
	}

	/**
	 * A JPacket pointer. This is a pointer type constructor that does not
	 * allocate any memory but its intended to be pointed at a scanner packet_t
	 * structure that contains meta information about the structure of the
	 * packet data buffer.
	 * <p>
	 * JPacket consists of 2 peers. The first and the main memory peering is
	 * with the packet_state_t structure which stores information about the
	 * decoded state of the packet, another words the result of the scanned
	 * packet data buffer. The second peer is to the actual packet data buffer
	 * which is a separate pointer.
	 * <h2>Peering struct packet_t</h2>
	 * This structure contains the "packet state". This is the decoded state
	 * which specifies what headers are in the buffer and at what offsets. This
	 * structure is the output of a JScanner.scan() method. The memory for this
	 * state can be anywhere, but by default JScanner stores it in a round-robin
	 * buffer it uses for decoding fast incoming packets. The state can easily
	 * be copied into another buffer for longer storage using such methods as
	 * <code>transferStateAndDataTo</code> which will copy the packet state
	 * and/or data buffer into another memory area, such as a direct ByteBuffer
	 * or JBuffer.
	 * </p>
	 * 
	 * @param type
	 *            the type
	 */
	public JPacket(Type type) {
		super(type);
		order(ByteOrder.BIG_ENDIAN);
	}

	/**
	 * Creates a new memory buffer of given size for internal usage.
	 * 
	 * @param size
	 *            size in bytes
	 */
	public void allocate(int size) {
		pool.allocate(size, memory);
	}

	/**
	 * Filter existing header instances by specified type.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param type
	 *            the clazz
	 * @return the iterable
	 * @since 1.4
	 */
	public <T> Iterable<T> filterByType(final Class<T> type) {
		return new Iterable<T>() {

			@Override
			public Iterator<T> iterator() {
				return JPacket.this.iterator(type);
			}
		};
	}

	/**
	 * Gets the size of the current internal memory buffer.
	 * 
	 * @return length in bytes
	 */
	public int getAllocatedMemorySize() {
		if (!memory.isInitialized()) {
			return 0;
		}

		return memory.size();
	}

	/**
	 * Gets the capture header as generated by the native capture library.
	 * 
	 * @return capture header
	 */
	public abstract JCaptureHeader getCaptureHeader();

	/**
	 * Gets the unique flow-key for this packet. This method instantiates a
	 * flow-key object and peers is with native flow-key state. The flow-key
	 * reference is retained and returned on any subsequent invocations.
	 * <p>
	 * Flow-keys are generated for each packet and can be used to group packets
	 * into similar group of packets into flows. Flows associate packets that
	 * are flowing in the same or are part of the same group of packets. For
	 * example, TCP/IP group of packets will be grouped into flows, by
	 * generating appropriate flow-keys, so that all packets part of the same
	 * TCP stream, will have the exact same flow-key generated, allowing those
	 * packets to be grouped into a single flow. Flow-keys can be uni or bi
	 * directional.
	 * </p>
	 * <p>
	 * Uni-directional flow, is generated for packets that should be grouped, or
	 * belong to the same flow, where packets are sent from System A to System
	 * B, in a single or uni direction. Bi-directional keys are generated for
	 * packets that should belong to the same flow, in both directions. Packets
	 * that are sent from System A to System B and packets that are sent from
	 * System B to System A.
	 * </p>
	 * <p>
	 * The criteria used for generating flow-keys is different for each packet
	 * based on protocol headers present in the packet. As an example, a
	 * flow-key for a Ethernet/Ip4/Tcp packet is generated based on source and
	 * destination ethernet addresses, source and destination Ip4 address, the
	 * Ip4 protocol/type number 16 which signifies that next protocol is TCP and
	 * source and destination TCP port numbers. The flow-key generated for this
	 * example is bidirectional, meaning that packets belonging to the same TCP
	 * conversation in both directions between System A and System B will have
	 * the exact same flow-key generated.
	 * </p>
	 * 
	 * 
	 * @return a unique flow-key object
	 */
	public JFlowKey getFlowKey() {
		return state.getFlowKey();
	}

	/**
	 * Gets the unique flow-key for this packet. This method peers the
	 * <p>
	 * Flow-keys are generated for each packet and can be used to group packets
	 * into similar group of packets into flows. Flows associate packets that
	 * are flowing in the same or are part of the same group of packets. For
	 * example, TCP/IP group of packets will be grouped into flows, by
	 * generating appropriate flow-keys, so that all packets part of the same
	 * TCP stream, will have the exact same flow-key generated, allowing those
	 * packets to be grouped into a single flow. Flow-keys can be uni or bi
	 * directional.
	 * </p>
	 * <p>
	 * Uni-directional flow, is generated for packets that should be grouped, or
	 * belong to the same flow, where packets are sent from System A to System
	 * B, in a single or uni direction. Bi-directional keys are generated for
	 * packets that should belong to the same flow, in both directions. Packets
	 * that are sent from System A to System B and packets that are sent from
	 * System B to System A.
	 * </p>
	 * <p>
	 * The criteria used for generating flow-keys is different for each packet
	 * based on protocol headers present in the packet. As an example, a
	 * flow-key for a Ethernet/Ip4/Tcp packet is generated based on source and
	 * destination ethernet addresses, source and destination Ip4 address, the
	 * Ip4 protocol/type number 16 which signifies that next protocol is TCP and
	 * source and destination TCP port numbers. The flow-key generated for this
	 * example is bidirectional, meaning that packets belonging to the same TCP
	 * conversation in both directions between System A and System B will have
	 * the exact same flow-key generated.
	 * </p>
	 * 
	 * 
	 * @return a unique flow-key object
	 */
	public JFlowKey getFlowKey(JFlowKey key) {
		key.peer(state);

		return key;
	}

	/**
	 * Returns the frame number as assigned by either the packet scanner or
	 * analyzers.
	 * 
	 * @return zero based frame number
	 */
	public long getFrameNumber() {
		return state.getFrameNumber() + 1;
	}

	/**
	 * Peers the supplied header with the native header state structure and
	 * packet data buffer.
	 * 
	 * @param <T>
	 *            name of the header
	 * @param header
	 *            instance of a header object
	 * @return the supplied instance of the header
	 */
	public <T extends JHeader> T getHeader(T header) {
		return getHeader(header, 0);
	}

	/**
	 * Peers the supplied header with the native header state structure and
	 * packet data buffer. This method allows retrieval of a specific instance
	 * of a header if more than one instance has been found.
	 * 
	 * @param <T>
	 *            name of the header
	 * @param header
	 *            instance of a header object
	 * @param instance
	 *            instance number of the header since more than one header of
	 *            the same type can exist in the same packet buffer
	 * @return the supplied instance of the header
	 */
	public <T extends JHeader> T getHeader(T header, int instance) {
		check();

		final int id = header.getId();
		if (!hasHeader(id)) { // Simple bitmap test speeds things up
			return null;
		}

		final int index = this.state.findHeaderIndex(id, instance);
		if (index == -1) {
			return null;
		}

		return getHeaderByIndex(index, header);
	}

	/**
	 * Peers a header with specific index, not the numerical header ID assigned
	 * by JRegistry, of a header.
	 * 
	 * @param <T>
	 *            name of the header
	 * @param index
	 *            index into the header array the scanner has found
	 * @param header
	 *            instance of a header object
	 * @return the supplied header
	 * @throws IndexOutOfBoundsException
	 *             the index out of bounds exception
	 */
	public <T extends JHeader> T getHeaderByIndex(int index, T header)
			throws IndexOutOfBoundsException {

		final int id = header.getId();
		if (!hasHeader(id)) { // Simple bitmap test speeds things up
			return null;
		}

		JHeader.State hstate = header.getState();
		this.state.peerHeaderByIndex(index, hstate);
		
		final int offset = hstate.getOffset();
		final int length = hstate.getLength();

		header.peer(this, offset, length);
		header.setPacket(this); // Set the header's parent
		header.setIndex(index); // Set the header's index into packet structure
		header.decode(); // Call its decode routine if defined

		return header;

	}

	/**
	 * Gets number of headers found within the packet header. The last header
	 * may or may not be the builtin Payload header
	 * 
	 * @return number of headers present
	 */
	public int getHeaderCount() {
		return this.state.getHeaderCount();
	}

	/**
	 * Gets the numerical ID of the header at specified index into header array
	 * as found by the packet scanner.
	 * 
	 * @param index
	 *            index into the header array
	 * @return numerical ID of the header found at the specific index
	 */
	public int getHeaderIdByIndex(int index) {
		return this.state.getHeaderIdByIndex(index);
	}

	/**
	 * Gets number of headers with the same numerical ID as assigned by
	 * JRegistry within the same packet. For example Ip4 in ip4 packet would
	 * contain 2 instances of Ip4 header.
	 * 
	 * @param id
	 *            numerical ID of the header to search for
	 * @return number of headers of the same type in the packet
	 */
	public int getHeaderInstanceCount(int id) {
		return this.state.getInstanceCount(id);
	}

	/**
	 * Gets the memory buffer with the supplied byte array data copied into it.
	 * The internal memory buffer is allocated if necessary.
	 * 
	 * @param buffer
	 *            source array buffer to copy data out of
	 * @return the memory buffer
	 */
	protected JBuffer getMemoryBuffer(byte[] buffer) {
		pool.allocate(buffer.length, memory);
		memory.transferFrom(buffer);

		return memory;
	}

	/**
	 * Gets the memory buffer with the supplied ByteBuffer data copied into it.
	 * The internal memory buffer is allocated if neccessary.
	 * 
	 * @param buffer
	 *            source array buffer to copy data out of
	 * @return the memory buffer
	 * @throws PeeringException
	 *             the peering exception
	 */
	protected JBuffer getMemoryBuffer(ByteBuffer buffer)
			throws PeeringException {
		memory.peer(buffer);

		return memory;
	}

	/**
	 * Retrieves a memory buffer, allocated if necessary, at least minSize in
	 * bytes. If existing buffer is already big enough, it is returned,
	 * otherwise a new buffer is allocated and the existing one released.
	 * 
	 * @param minSize
	 *            minimum number of bytes required for the buffer
	 * @return the buffer
	 */
	protected JBuffer getMemoryBuffer(int minSize) {
		if (!memory.isInitialized() || memory.size() < minSize) {
			allocate(minSize);
		}

		return memory;
	}

	/**
	 * Gets the memory buffer with the supplied JBuffer data copied into it. The
	 * internal memory buffer is allocated if necessary.
	 * 
	 * @param buffer
	 *            source array buffer to copy data out of
	 * @return the memory buffer
	 */
	protected JBuffer getMemoryBuffer(JBuffer buffer) {
		memory.peer(buffer);

		return memory;
	}

	/**
	 * Gets the wire length of the packet. This is the original length as seen
	 * on the wire. This length may different JPacket.size() length, as the
	 * packet may have been truncated at the time of the capture.
	 * 
	 * @return original packet length
	 */
	public int getPacketWirelen() {
		return getCaptureHeader().wirelen();
	}

	/**
	 * Gets the current default scanner.
	 * 
	 * @return current default scanner
	 * @deprecated use static {@link JPacket#getDefaultScanner()} instead
	 */
	@Deprecated
	public JScanner getScanner() {
		return defaultScanner.get();
	}

	/**
	 * Gets the peered packet state object
	 * 
	 * @return packet native state
	 */
	public State getState() {
		return state;
	}

	/**
	 * Gets the total size of this packet. The size includes state, header and
	 * packet data.
	 * 
	 * @return size in bytes
	 */
	public abstract int getTotalSize();

	/**
	 * Checks if all of the headers present in the bitmask are found in the
	 * packet.
	 * 
	 * @param mask
	 *            bitmask of encoded headers
	 * @return true if all of the headers are present
	 * @since 1.4
	 */
	public boolean hasAllHeaders(final long mask) {
		final long headerMap =
				state.get64BitHeaderMap(JProtocol.maskToGroup(mask));
		return (headerMap & mask) == mask;
	}

	/**
	 * Checks if any of the headers present in the bitmask are found in the
	 * packet.
	 * 
	 * @param mask
	 *            bitmask of encoded headers
	 * @return true if any (1 or more) of the headers in the bitmask are present
	 * @see JProtocol#createMaskFromIds(int...)
	 * @see JProtocol#createMaskFromMasks(long...)
	 * @since 1.4
	 */
	public boolean hasAnyHeader(final long mask) {
		final long headerMap =
				state.get64BitHeaderMap(JProtocol.maskToGroup(mask));
		return (headerMap & mask & JProtocol.BITMASK_PROTCOL_MASK) != 0
				&& (headerMap & JProtocol.BITMASK_GROUP_MASK) == (mask & JProtocol.BITMASK_GROUP_MASK);
	}

	/**
	 * Checks if header with specified numerical ID exists within the decoded
	 * packet.
	 * 
	 * @param id
	 *            protocol header ID as assigned by JRegistry
	 * @return true header exists, otherwise false
	 */
	public boolean hasHeader(final int id) {
		final long headerMap = state.get64BitHeaderMap(JProtocol.idToGroup(id));
		final long mask = JProtocol.idToMask(id);
		return (headerMap & mask) != 0;
	}

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet.
	 * 
	 * @param id
	 *            protocol header ID as assigned by JRegistry
	 * @param instance
	 *            instance number of the specific header within the packet
	 * @return true header exists, otherwise false
	 */
	public boolean hasHeader(int id, int instance) {
		check();

		final int index = this.state.findHeaderIndex(id, instance);
		if (index == -1) {
			return false;
		}

		return true;
	}

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet and if found peers the supplied header with the
	 * located header within the decoded packet. This method executes as
	 * hasHeader followed by getHeader if found more efficiently.
	 * 
	 * @param <T>
	 *            name of the header type
	 * @param header
	 *            protocol header object instance
	 * @return true header exists, otherwise false
	 */
	public <T extends JHeader> boolean hasHeader(T header) {
		return getHeader(header, 0) != null;
	}

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet and if found peers the supplied header with the
	 * located header within the decoded packet. This method executes as
	 * hasHeader followed by getHeader if found more efficiently.
	 * 
	 * @param <T>
	 *            name of the header type
	 * @param header
	 *            protocol header object instance
	 * @param instance
	 *            instance number of the specific header within the packet
	 * @return true header exists, otherwise false
	 */
	public <T extends JHeader> boolean hasHeader(T header, int instance) {
		check();

		int id = header.getId();

		/*
		 * Make sure we have at least 1 header of our type
		 */
		if (!hasHeader(id)) {
			return false;
		}

		/*
		 * Now find the exact instance of the header, 1st, 2nd, or 3rd, etc...
		 */
		final int index = this.state.findHeaderIndex(id, instance);
		if (index == -1) {
			return false;
		}

		/*
		 * Peer state to header object
		 */
		getHeaderByIndex(index, header);

		/*
		 * We are done, header found and peered
		 */
		return true;
	}

	/**
	 * Uses a thread-local based <code>JHeaderPool</code> to iterate over all
	 * the headers within a packet.
	 * 
	 * @return the iterator
	 * @see java.lang.Iterable#iterator()
	 * @since 1.4
	 */
	@Override
	public Iterator<JHeader> iterator() {
		final int count = state.getHeaderCount();

		return new Iterator<JHeader>() {
			int i = 0;

			@Override
			public boolean hasNext() {
				return i < count;
			}

			@Override
			public JHeader next() {
				if (i >= count) {
					throw new IllegalStateException("must first call hasNext");
				}

				final int id = JPacket.this.getHeaderIdByIndex(i++);
				final JHeader header = headerPool.getHeader(id);

				return JPacket.this.getHeader(header);
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}

		};
	}

	/**
	 * Uses a thread-local based <code>JHeaderPool</code> to iterate over all
	 * the headers within a packet that are instances of the specified type.
	 * 
	 * @param <T>
	 *            the generic type
	 * @param type
	 *            the class used to check if a header is in assignable to this
	 *            type
	 * @return the iterator
	 */
	public <T> Iterator<T> iterator(final Class<T> type) {
		final int count = state.getHeaderCount();

		return new Iterator<T>() {
			JHeader header;
			int i = 0;

			private void advance() {
				for (; i < count; i++) {
					final int id = JPacket.this.getHeaderIdByIndex(i);
					header = headerPool.getHeader(id);

					if (type.isInstance(header)) {
						break;
					}
				}
			}

			@Override
			public boolean hasNext() {
				advance();

				return i < count;
			}

			@SuppressWarnings("unchecked")
			@Override
			public T next() {
				if (header == null) {
					throw new IllegalStateException("must first call hasNext");
				}

				i++;
				return (T) JPacket.this.getHeader(header);
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	/**
	 * Method recalculates header CRC for every header that supports
	 * JHeaderChecksum interface. The new CRC values are written back into the
	 * headers.
	 */
	public void recalculateAllChecksums() {
		for (final JHeaderChecksum header : filterByType(JHeaderChecksum.class)) {
			header.recalculateChecksum();
		}
	}

	/**
	 * Calculates the number of bytes remaining within the packet given a
	 * specific offset.
	 * 
	 * @param offset
	 *            offset into the packet in bytes
	 * @return number of bytes remaining from specified offset
	 */
	public int remaining(int offset) {
		return size() - offset;
	}

	/**
	 * Calculates the remaining number of bytes within the packet buffer taking
	 * into account offset and length of a header supplied. The smaller of the 2
	 * is returned. This should typically be the length field unless the header
	 * has been truncated and remaining number of bytes is less.
	 * 
	 * @param offset
	 *            offset of the header to take into account
	 * @param length
	 *            length of the header
	 * @return smaller number of bytes either remaining or legth
	 */
	public int remaining(int offset, int length) {
		final int remaining = size() - offset;

		return (remaining >= length) ? length : remaining;
	}

	/**
	 * Scan and decode the packet using current scanner. The new packet state
	 * replaces any existing packet state already assigned to this packet.
	 * 
	 * @param id
	 *            numerical ID as assigned by JRegistry of the first protocol
	 *            header to be found in the packet, the DLT
	 */
	public void scan(int id) {
		getDefaultScanner().scan(this, id, getCaptureHeader().wirelen());
	}

	/**
	 * Formats packet raw data as a hexdump output and marks header boundaries
	 * with special characters.
	 * 
	 * @return the string
	 */
	@Override
	public String toHexdump() {
		if (state.isInitialized()) {
			return FormatUtils.hexdump(this);
		} else {
			byte[] b = this.getByteArray(0, this.size());
			return FormatUtils.hexdump(b);
		}
	}

	/**
	 * Generates text formatted output using the default builtin formatter. The
	 * default is to generate TextFormatter that uses a StringBuilder for output
	 * buffer and generate a single string that is returned from here.
	 * <p>
	 * This method is multi-thread safe, but not reentrant from the same thread.
	 * </p>
	 * 
	 * @return formatted output of this packet
	 */
	@Override
	public String toString() {
		TextFormatter out = formatterPool.get();
		out.reset();
		try {
			out.format(this);
			return out.toString();
		} catch (Exception e) {
			throw new RuntimeException(out.toString(), e);
		}
	}
}
