/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/** This class implements the sort interface using primitive int arrays as 
 * the data structures (that is why this class is called 'BasicType'SorterBase)
 */
package org.apache.hadoop.mapred;
import java.io.DataOutputStream;
import java.io.IOException;
import org.apache.hadoop.io.DataOutputBuffer;
import org.apache.hadoop.io.OutputBuffer;
import org.apache.hadoop.io.RawComparator;
import org.apache.hadoop.io.SequenceFile.ValueBytes;
import org.apache.hadoop.util.Progress;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.io.SequenceFile.Sorter.RawKeyValueIterator;
import org.apache.hadoop.util.Progressable;

class MRSortResultIterator implements RawKeyValueIterator {
  
  private int count;
  private int[] pointers;
  private int[] startOffsets;
  private int[] keyLengths;
  private int[] valLengths;
  private int currStartOffsetIndex;
  private int currIndexInPointers;
  private OutputBuffer keyValBuffer;
  private DataOutputBuffer key = new DataOutputBuffer();
  private InMemUncompressedBytes value = new InMemUncompressedBytes();
  
  public MRSortResultIterator(OutputBuffer keyValBuffer, 
                              int []pointers, int []startOffsets,
                              int []keyLengths, int []valLengths) {
    this.count = pointers.length;
    this.pointers = pointers;
    this.startOffsets = startOffsets;
    this.keyLengths = keyLengths;
    this.valLengths = valLengths;
    this.keyValBuffer = keyValBuffer;
  }
  
  public Progress getProgress() {
    return null;
  }
  
  public DataOutputBuffer getKey() throws IOException {
    int currKeyOffset = startOffsets[currStartOffsetIndex];
    int currKeyLength = keyLengths[currStartOffsetIndex];
    //reuse the same key
    key.reset();
    key.write(keyValBuffer.getData(), currKeyOffset, currKeyLength);
    return key;
  }

  public ValueBytes getValue() throws IOException {
    //value[i] is stored in the following byte range:
    //startOffsets[i] + keyLengths[i] through valLengths[i]
    value.reset(keyValBuffer,
                startOffsets[currStartOffsetIndex] + keyLengths[currStartOffsetIndex],
                valLengths[currStartOffsetIndex]);
    return value;
  }

  public boolean next() throws IOException {
    if (count == currIndexInPointers)
      return false;
    currStartOffsetIndex = pointers[currIndexInPointers];
    currIndexInPointers++;
    return true;
  }
  
  public void close() {
    return;
  }
  
  //An implementation of the ValueBytes interface for the in-memory value
  //buffers. 
  private static class InMemUncompressedBytes implements ValueBytes {
    private byte[] data;
    int start;
    int dataSize;
    private void reset(OutputBuffer d, int start, int length) 
      throws IOException {
      data = d.getData();
      this.start = start;
      dataSize = length;
    }
            
    public int getSize() {
      return dataSize;
    }
            
    public void writeUncompressedBytes(DataOutputStream outStream)
      throws IOException {
      outStream.write(data, start, dataSize);
    }

    public void writeCompressedBytes(DataOutputStream outStream) 
      throws IllegalArgumentException, IOException {
      throw
        new IllegalArgumentException("UncompressedBytes cannot be compressed!");
    }
  
  } // InMemUncompressedBytes

}