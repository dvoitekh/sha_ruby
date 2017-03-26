# see Columnar transposition algorithm
class TranspositionCipher
  def initialize(text, table_width)
    @text = text
    @table_width = table_width
  end

  def encrypt
    Array.new(@table_width).map { [] }.tap do |table|
      @text.chars.each_with_index { |c, i| table[i % @table_width] << c }
    end.map(&:join).join
  end

  def decrypt
    raws_count = (@text.length.to_f / @table_width).ceil
    whole_columns_count = @text.length % @table_width
    columns = (@text.slice!(0...whole_columns_count * raws_count).scan(/.{1,#{raws_count}}/) + @text.scan(/.{1,#{raws_count - 1}}/))
    columns[0].chars.zip(*columns[1..-1].map(&:chars)).flatten.compact.join
  end
end
